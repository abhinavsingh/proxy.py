from __future__ import annotations

import abc
import math
import time

from logged_groups import logged_group
from typing import Dict, Optional, Any

from solana.transaction import AccountMeta, Transaction, PublicKey
from solana.blockhash import Blockhash

from .neon_tx_stages import NeonCreateAccountTxStage, NeonCreateERC20TxStage, NeonCreateContractTxStage, \
                            NeonResizeContractTxStage

from .operator_resource_list import OperatorResourceInfo
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.neon_instruction import NeonInstruction as NeonIxBuilder
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.solana_receipt_parser import SolTxError, SolReceiptParser
from ..common_neon.eth_proto import Trx as EthTx
from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo
from ..common_neon.errors import EthereumError
from ..common_neon.types import NeonTxPrecheckResult, NeonEmulatingResult
from ..common_neon.environment_data import RETRY_ON_FAIL
from ..common_neon.elf_params import ElfParams
from ..common_neon.utils import get_holder_msg
from ..common_neon.evm_decoder import decode_neon_tx_result
from ..memdb.memdb import MemDB, NeonPendingTxInfo


@logged_group("neon.Proxy")
class NeonTxSender:
    def __init__(self, db: MemDB, solana: SolanaInteractor, eth_tx: EthTx, steps: int):
        self._db = db
        self.eth_tx = eth_tx
        self.neon_sign = '0x' + eth_tx.hash_signed().hex()
        self.steps = steps
        self.waiter = self
        self.solana = solana
        self._resource_list = None
        self.resource = None
        self.signer = None
        self.operator_key = None
        self.builder = None

        self._pending_tx = None

        self.eth_sender = '0x' + eth_tx.sender()
        self.deployed_contract = eth_tx.contract()
        if self.deployed_contract:
            self.deployed_contract = '0x' + self.deployed_contract
        self.to_address = eth_tx.toAddress.hex()
        if self.to_address:
            self.to_address = '0x' + self.to_address


        self.create_account_tx = TransactionWithComputeBudget()
        self.account_txs_name = ''
        self._resize_contract_list = []
        self._create_account_list = []
        self._eth_meta_dict: Dict[str, AccountMeta] = dict()

    def execute(self, precheck_result: NeonTxPrecheckResult) -> NeonTxResultInfo:
        self._validate_pend_tx()
        self._prepare_execution(precheck_result.emulating_result)
        return self._execute(precheck_result)

    def set_resource(self, resource: Optional[OperatorResourceInfo]):
        self.resource = resource
        self.signer = resource.signer
        self.operator_key = resource.public_key()
        self.builder = NeonIxBuilder(self.operator_key)

    def clear_resource(self):
        self.resource = None
        self.operator_key = None
        self.builder = None

    def _validate_pend_tx(self):
        operator = f'{str(self.resource.public_key())}:{self.resource.rid}'
        self._pending_tx = NeonPendingTxInfo(neon_sign=self.neon_sign, operator=operator, slot=0)
        self._pend_tx_into_db(self.solana.get_recent_blockslot())

    def _execute(self, precheck_result: NeonTxPrecheckResult):

        for Strategy in [SimpleNeonTxStrategy, IterativeNeonTxStrategy, HolderNeonTxStrategy, NoChainIdNeonTxStrategy]:
            try:
                strategy = Strategy(precheck_result, self)
                if not strategy.is_valid:
                    self.debug(f'Skip strategy {Strategy.NAME}: {strategy.error}')
                    continue

                self.debug(f'Use strategy {Strategy.NAME}')
                neon_res, sign_list = strategy.execute()
                self._submit_tx_into_db(neon_res, sign_list)
                return neon_res
            except Exception as e:
                if (not Strategy.IS_SIMPLE) or (not SolReceiptParser(e).check_if_budget_exceeded()):
                    raise

        self.error(f'No strategy to execute the Neon transaction: {self.eth_tx}')
        raise EthereumError(message="transaction is too big for execution")

    def on_wait_confirm(self, _, slot: int):
        self._pend_tx_into_db(slot)

    def _pend_tx_into_db(self, slot: int):
        """
        Transaction sender doesn't remove pending transactions!!!
        This protects the neon transaction execution from race conditions, when user tries to send transaction
        multiple time. User can send the same transaction after it complete too.

        Indexer will purge old pending transactions after finalizing slot.
        """
        if self._pending_tx and ((slot - self._pending_tx.slot) > 10):
            self.debug(f'Update pending transaction: diff {slot - self._pending_tx.slot}, set {slot}')
            self._pending_tx.slot = slot
            self._db.pend_transaction(self._pending_tx)

    def _submit_tx_into_db(self, neon_res: NeonTxResultInfo, sign_list: [str]):
        neon_tx = NeonTxInfo()
        neon_tx.init_from_eth_tx(self.eth_tx)
        self._db.submit_transaction(neon_tx, neon_res, sign_list)

    def _prepare_execution(self, emulating_result: NeonEmulatingResult):
        # Parse information from the emulator output
        self._parse_accounts_list(emulating_result['accounts'])
        self._parse_token_list(emulating_result['token_accounts'])
        self._parse_solana_list(emulating_result['solana_accounts'])

        eth_meta_list = list(self._eth_meta_dict.values())
        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in eth_meta_list]))

        # Build all instructions
        self._build_account_stage_list()

        self.builder.init_operator_ether(self.resource.ether)
        self.builder.init_eth_trx(self.eth_tx, eth_meta_list)
        self.builder.init_iterative(self.resource.storage, self.resource.holder, self.resource.rid)

    def _add_meta(self, pubkey: PublicKey, is_writable: bool):
        key = str(pubkey)
        if key in self._eth_meta_dict:
            self._eth_meta_dict[key].is_writable |= is_writable
        else:
            self._eth_meta_dict[key] = AccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)

    def _parse_accounts_list(self, emulated_result_accounts):
        for account_desc in emulated_result_accounts:
            if account_desc['new']:
                if account_desc['code_size']:
                    stage = NeonCreateContractTxStage(self, account_desc)
                    self._create_account_list.append(stage)
                elif account_desc['writable']:
                    stage = NeonCreateAccountTxStage(self, account_desc)
                    self._create_account_list.append(stage)
            elif account_desc['code_size'] and (account_desc['code_size_current'] < account_desc['code_size']):
                self._resize_contract_list.append(NeonResizeContractTxStage(self, account_desc))

            self._add_meta(account_desc['account'], True)
            if account_desc['contract']:
                self._add_meta(account_desc['contract'], account_desc['writable'])

    def _parse_token_list(self, emulated_result_token_accounts):
        for token_account in emulated_result_token_accounts:
            self._add_meta(token_account['key'], True)
            if token_account['new']:
                self._create_account_list.append(NeonCreateERC20TxStage(self, token_account))

    def _parse_solana_list(self, emulated_result_solana_accounts):
        for account_desc in emulated_result_solana_accounts:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

    def _build_account_stage_list(self):
        all_stages = self._create_account_list + self._resize_contract_list
        if not len(all_stages):
            return

        size_list = list(set([s.size for s in all_stages]))
        balance_list = self.solana.get_multiple_rent_exempt_balances_for_size(size_list)
        balance_map = {size: balance for size, balance in zip(size_list, balance_list)}
        name_dict = {}
        for s in all_stages:
            s.balance = balance_map[s.size]
            s.build()
            name_dict.setdefault(s.NAME, 0)
            name_dict[s.NAME] += 1

        for s in self._create_account_list:
            self.create_account_tx.add(s.tx)
        self.account_txs_name = ' + '.join([f'{name}({cnt})' for name, cnt in name_dict.items()])

    def build_account_tx_list(self, skip_create_accounts=False) -> [TransactionWithComputeBudget]:
        tx_list = [s.tx for s in self._resize_contract_list]
        if (not skip_create_accounts) and len(self._create_account_list):
            tx_list.append(self.create_account_tx)
        return tx_list

    def done_account_tx_list(self, skip_create_accounts=False):
        self._resize_contract_list.clear()
        if not skip_create_accounts:
            self._create_account_list.clear()
            self.create_account_tx.instructions.clear()


@logged_group("neon.Proxy")
class BaseNeonTxStrategy(metaclass=abc.ABCMeta):
    NAME = 'UNKNOWN STRATEGY'

    def __init__(self, precheck_result: NeonTxPrecheckResult, neon_tx_sender: NeonTxSender):
        self._precheck_result = precheck_result
        self.is_valid = False
        self.error = None
        self.s = neon_tx_sender
        self.steps = self.s.steps
        self.is_valid = self._validate()

    @abc.abstractmethod
    def execute(self) -> (NeonTxResultInfo, [str]):
        return NeonTxResultInfo(), []

    @abc.abstractmethod
    def build_tx(self, _=0) -> TransactionWithComputeBudget:
        return TransactionWithComputeBudget()

    @abc.abstractmethod
    def _validate(self) -> bool:
        return True

    def _validate_notdeploy_tx(self) -> bool:
        if self.s.deployed_contract:
            self.error = 'Deploy transaction'
            return False
        return True

    def _validate_txsize(self) -> bool:
        tx = self.build_tx()

        # Predefined blockhash is used only to check transaction size, this transaction won't be send to network
        tx.recent_blockhash = Blockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        tx.sign(self.s.resource.signer)
        try:
            tx.serialize()
            return True
        except Exception as err:
            if SolReceiptParser(err).check_if_big_transaction():
                self.error = 'Too big transaction size'
                return False
            self.error = str(err)
            raise

    def _validate_gas_limit(self):
        if not self._precheck_result.is_underpriced_tx_without_chainid:
            return True

        self.error = "Underpriced transaction without chain-id"
        return False


@logged_group("neon.Proxy")
class SimpleNeonTxSender(SolTxListSender):
    def __init__(self, strategy: BaseNeonTxStrategy, *args, **kwargs):
        SolTxListSender.__init__(self, *args, **kwargs)
        self._strategy = strategy
        self.neon_res = NeonTxResultInfo()

    def _on_success_send(self, tx: Transaction, receipt: {}):
        if not self.neon_res.is_valid():
            decode_neon_tx_result(self.neon_res, self._s.neon_sign, receipt).is_valid()
        super()._on_success_send(tx, receipt)

    def _on_post_send(self):
        if self.neon_res.is_valid():
            self.debug(f'Got Neon tx result: {self.neon_res}')
            self.clear()
        else:
            super()._on_post_send()

            if not len(self._tx_list):
                raise RuntimeError('Run out of attempts to execute transaction')


@logged_group("neon.Proxy")
class SimpleNeonTxStrategy(BaseNeonTxStrategy, abc.ABC):
    NAME = 'CallFromRawEthereumTX'
    IS_SIMPLE = True

    def __init__(self, *args, **kwargs):
        self._skip_create_account = False
        BaseNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        if (not self._validate_steps()) or (not self._validate_notdeploy_tx()) or (not self._validate_gas_limit()):
            return False

        # Attempting to include create accounts instructions into the transaction
        if self._validate_txsize():
            return True

        self._skip_create_account = not self._skip_create_account
        return self._validate_txsize()

    def _validate_steps(self) -> bool:
        steps_emulated = self._precheck_result.emulating_result["steps_executed"]
        if steps_emulated > self.steps:
            self.error = 'Too big number of EVM steps'
            return False
        return True

    def build_tx(self, _=0) -> TransactionWithComputeBudget:
        tx = TransactionWithComputeBudget()
        if not self._skip_create_account:
            tx.add(self.s.create_account_tx)
        tx.add(self.s.builder.make_noniterative_call_transaction(len(tx.instructions)))
        return tx

    def execute(self) -> (NeonTxResultInfo, [str]):
        signer = self.s.resource.signer
        tx_list = self.s.build_account_tx_list(self._skip_create_account)
        if len(tx_list) > 0:
            SolTxListSender(self.s, tx_list, self.s.account_txs_name).send(signer)
            self.s.done_account_tx_list(self._skip_create_account)

        tx_sender = SimpleNeonTxSender(self, self.s, [self.build_tx()], self.NAME).send(signer)
        if not tx_sender.neon_res.is_valid():
            raise tx_sender.raise_budget_exceeded()
        return tx_sender.neon_res, tx_sender.success_sign_list


@logged_group("neon.Proxy")
class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, *args, **kwargs):
        SimpleNeonTxSender.__init__(self, *args, **kwargs)
        self._is_canceled = False
        self._postponed_exception = None

    def _try_lock_accounts(self):
        time.sleep(0.4)  # one block time

        # send one transaction to get lock, and only after that send all others
        tx = self._blocked_account_list.pop()
        self._set_tx_blockhash(tx)
        self._tx_list = [tx]

        # prevent the transaction sending one at a time
        self._pending_list += self._blocked_account_list
        self._blocked_account_list.clear()

    def _cancel(self):
        self.debug(f'Cancel the transaction')
        self.clear()
        self._name = 'CancelWithNonce'
        self._is_canceled = True
        self._retry_idx = 0  # force the cancel sending
        tx = TransactionWithComputeBudget()
        tx.add(self._s.builder.make_cancel_instruction())
        self._tx_list = [tx]

    def _decrease_steps(self):
        prev_total_cnt = len(self._get_full_list())
        prev_steps = self._strategy.steps
        total_steps = prev_total_cnt * self._strategy.steps

        if self._strategy.steps <= 10:
            return self._cancel()

        if self._strategy.steps > 170:
            self._strategy.steps -= 150
        else:
            self._strategy.steps = 10
        total_cnt = math.ceil(total_steps / self._strategy.steps)

        self.debug(f'Decrease EVM steps from {prev_steps} to {self._strategy.steps}, ' +
                   f'iterations increase from {prev_total_cnt} to {total_cnt}')

        self.clear()
        self._tx_list = [self._strategy.build_tx(idx) for idx in range(total_cnt)]

    def _on_success_send(self, tx: Transaction, receipt: {}):
        if self._is_canceled:
            # Transaction with cancel is confirmed
            self.neon_res.canceled(receipt)
        else:
            super()._on_success_send(tx, receipt)

    def _set_postponed_exception(self, exception: Exception):
        if not self._postponed_exception:
            self._postponed_exception = exception

    def _raise_error(self):
        assert self._postponed_exception is not None
        raise self._postponed_exception

    def _on_post_send(self):
        # Result is received
        if self.neon_res.is_valid():
            self.debug(f'Got Neon tx {"cancel" if self._is_canceled else "result"}: {self.neon_res}')
            if self._is_canceled and self._postponed_exception:
                self._raise_error()
            return self.clear()

        if len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            time.sleep(1)

        # Unknown error happens - cancel the transaction
        if len(self._unknown_error_list):
            self._set_postponed_exception(SolTxError(self._unknown_error_list[0]))
            if self._is_canceled:
                self._raise_error()

            self._unknown_error_list.clear()
            if len(self.success_sign_list):
                return self._cancel()
            self._raise_error()

        # There is no more retries to send transactions
        if self._retry_idx >= RETRY_ON_FAIL:
            self._set_postponed_exception(EthereumError(message='No more retries to complete transaction!'))
            if (not self._is_canceled) and len(self.success_sign_list):
                return self._cancel()
            self._raise_error()

        # Blockhash is changed (((
        if len(self._bad_block_list):
            self._blockhash = None

        # Accounts are blocked, so try to lock them
        if len(self._blocked_account_list):
            return self._try_lock_accounts()

        # Compute budged is exceeded, so decrease EVM steps per iteration
        if len(self._budget_exceeded_list):
            return self._decrease_steps()

        self._move_txlist()

        # if no iterations and no result then add the additional iteration
        if not len(self._tx_list):
            self.debug('No result -> add the additional iteration')
            self._tx_list.append(self._strategy.build_tx())


@logged_group("neon.Proxy")
class IterativeNeonTxStrategy(BaseNeonTxStrategy, abc.ABC):
    NAME = 'PartialCallOrContinueFromRawEthereumTX'
    IS_SIMPLE = False

    def __init__(self, *args, **kwargs):
        BaseNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        return (self._validate_notdeploy_tx() and
                self._validate_txsize() and
                self._validate_evm_steps() and
                self._validate_gas_limit())

    def _validate_evm_steps(self):
        if self._precheck_result.emulating_result["steps_executed"] > (self.s.steps * 25):
            self.error = 'Big number of EVM steps'
            return False
        return True

    def build_tx(self, idx=0) -> TransactionWithComputeBudget:
        # generate unique tx
        tx = TransactionWithComputeBudget()
        tx.add(self.s.builder.make_partial_call_or_continue_transaction(self.steps + idx, len(tx.instructions)))
        return tx

    def _build_preparation_tx_list(self) -> [TransactionWithComputeBudget]:
        self._preparation_txs_name = self.s.account_txs_name
        return self.s.build_account_tx_list(False)

    def execute(self) -> (NeonTxResultInfo, [str]):
        signer = self.s.resource.signer
        tx_list = self._build_preparation_tx_list()
        if len(tx_list):
            SolTxListSender(self.s, tx_list, self._preparation_txs_name).send(signer)
            self.s.done_account_tx_list()

        steps_emulated = self._precheck_result.emulating_result["steps_executed"]
        cnt = math.ceil(steps_emulated / self.steps)
        cnt = math.ceil(steps_emulated / (self.steps - cnt))
        if steps_emulated > 200:
            cnt += 2  # +1 on begin, +1 on end
        tx_list = [self.build_tx(idx) for idx in range(cnt)]
        self.debug(f'Total iterations {len(tx_list)} for {steps_emulated} ({self.steps}) EVM steps')
        tx_sender = IterativeNeonTxSender(self, self.s, tx_list, self.NAME)
        tx_sender.send(signer)
        return tx_sender.neon_res, tx_sender.success_sign_list


@logged_group("neon.Proxy")
class HolderNeonTxStrategy(IterativeNeonTxStrategy, abc.ABC):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs):
        IterativeNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        return (self._validate_txsize() and
                self._validate_gas_limit())

    def build_tx(self, idx=0) -> TransactionWithComputeBudget:
        tx = TransactionWithComputeBudget()
        tx.add(self.s.builder.make_partial_call_or_continue_from_account_data_instruction(self.steps, idx))
        return tx

    def _build_preparation_tx_list(self) -> [TransactionWithComputeBudget]:
        tx_list = super()._build_preparation_tx_list()

        # write eth transaction to the holder account
        msg = get_holder_msg(self.s.eth_tx)

        offset = 0
        rest = msg
        cnt = 0
        holder_msg_size = ElfParams().holder_msg_size
        while len(rest):
            (part, rest) = (rest[:holder_msg_size], rest[holder_msg_size:])
            tx = TransactionWithComputeBudget()
            tx.add(self.s.builder.make_write_instruction(offset, part))
            tx_list.append(tx)
            offset += len(part)
            cnt += 1

        if len(self._preparation_txs_name):
            self._preparation_txs_name += ' + '
        self._preparation_txs_name += f'WriteWithHolder({cnt})'
        return tx_list


@logged_group("neon.Proxy")
class NoChainIdNeonTxStrategy(HolderNeonTxStrategy, abc.ABC):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        HolderNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        if not self._precheck_result.is_underpriced_tx_without_chainid:
            self.error = 'Normal transaction'
            return False

        return self._validate_txsize()

    def build_tx(self, idx=0) -> TransactionWithComputeBudget:
        tx = TransactionWithComputeBudget()
        tx.add(self.s.builder.make_partial_call_or_continue_from_account_data_no_chainid_instruction(self.steps, idx))
        return tx
