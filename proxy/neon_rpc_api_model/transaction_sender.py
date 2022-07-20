from __future__ import annotations

import abc
import math
import time
import copy

from logged_groups import logged_group
from typing import Dict, Optional, List, Tuple, Any, cast

from solana.transaction import AccountMeta as SolanaAccountMeta, Transaction, PublicKey
from solana.blockhash import Blockhash
from solana.account import Account as SolanaAccount

from .neon_tx_stages import NeonTxStage, NeonCreateAccountTxStage, NeonCreateERC20TxStage, NeonCreateContractTxStage
from .neon_tx_stages import NeonResizeContractTxStage

from .operator_resource_list import OperatorResourceInfo
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_tx_list_sender import SolTxListSender, IConfirmWaiter
from ..common_neon.solana_receipt_parser import SolTxError, SolReceiptParser
from ..common_neon.eth_proto import Trx as EthTx
from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo
from ..common_neon.errors import EthereumError
from ..common_neon.types import NeonTxPrecheckResult, NeonEmulatingResult
from ..common_neon.environment_data import RETRY_ON_FAIL, EVM_STEP_COUNT
from ..common_neon.elf_params import ElfParams

from ..common_neon.solana_alt import AddressLookupTableInfo
from ..common_neon.solana_alt_builder import AddressLookupTableTxBuilder, AddressLookupTableTxList
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue
from ..common_neon.solana_v0_transaction import V0Transaction

from ..memdb.memdb import MemDB, NeonPendingTxInfo


@logged_group("neon.Proxy")
class AccountTxListBuilder:
    def __init__(self, solana: SolanaInteractor, builder: NeonIxBuilder):
        self._solana = solana
        self._builder = builder
        self._name = ''
        self._resize_contract_list: List[NeonTxStage] = []
        self._create_account_list: List[NeonTxStage] = []
        self._eth_meta_dict: Dict[str, SolanaAccountMeta] = dict()

    def build_tx(self, emulating_result: NeonEmulatingResult) -> None:
        # Parse information from the emulator output
        self._parse_accounts_list(emulating_result['accounts'])
        self._parse_token_list(emulating_result['token_accounts'])
        self._parse_solana_list(emulating_result['solana_accounts'])

        eth_meta_list = list(self._eth_meta_dict.values())
        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in eth_meta_list]))
        self._builder.init_eth_accounts(eth_meta_list)

        # Build all instructions
        self._build_account_stage_list()

    @property
    def name(self) -> str:
        return self._name

    def _add_meta(self, pubkey: PublicKey, is_writable: bool) -> None:
        key = str(pubkey)
        if key in self._eth_meta_dict:
            self._eth_meta_dict[key].is_writable |= is_writable
        else:
            self._eth_meta_dict[key] = SolanaAccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)

    def _parse_accounts_list(self, emulated_result_account_list: List[Dict[str, Any]]) -> None:
        for account_desc in emulated_result_account_list:
            if account_desc['new']:
                if account_desc['code_size']:
                    stage = NeonCreateContractTxStage(self._builder, account_desc)
                    self._create_account_list.append(stage)
                elif account_desc['writable']:
                    stage = NeonCreateAccountTxStage(self._builder, account_desc)
                    self._create_account_list.append(stage)
            elif account_desc['code_size'] and (account_desc['code_size_current'] < account_desc['code_size']):
                self._resize_contract_list.append(NeonResizeContractTxStage(self._builder, account_desc))

            self._add_meta(account_desc['account'], True)
            if account_desc['contract']:
                self._add_meta(account_desc['contract'], account_desc['writable'])

    def _parse_token_list(self, emulated_result_token_accounts: List[Dict[str, Any]]) -> None:
        for token_account in emulated_result_token_accounts:
            self._add_meta(token_account['key'], True)
            if token_account['new']:
                self._create_account_list.append(NeonCreateERC20TxStage(self._builder, token_account))

    def _parse_solana_list(self, emulated_result_solana_account_list: List[Dict[str, Any]]) -> None:
        for account_desc in emulated_result_solana_account_list:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

    def _build_account_stage_list(self) -> None:
        if not self.has_tx_list():
            return

        all_stage_list = self._create_account_list + self._resize_contract_list
        size_list = list(set([s.size for s in all_stage_list]))
        balance_list = self._solana.get_multiple_rent_exempt_balances_for_size(size_list)
        balance_map = {size: balance for size, balance in zip(size_list, balance_list)}
        name_dict = {}
        for s in all_stage_list:
            s.set_balance(balance_map[s.size])
            s.build()
            name_dict.setdefault(s.NAME, 0)
            name_dict[s.NAME] += 1

        self._name = ' + '.join([f'{name}({cnt})' for name, cnt in name_dict.items()])

    def has_tx_list(self) -> bool:
        return len(self._resize_contract_list) > 0 or len(self._create_account_list) > 0

    def get_tx_list(self) -> List[Transaction]:
        tx_list = [s.tx for s in (self._resize_contract_list + self._create_account_list)]
        return tx_list

    def clear_tx_list(self) -> None:
        self._resize_contract_list.clear()
        self._create_account_list.clear()


class NeonTxSendCtx:
    def __init__(self, solana: SolanaInteractor, resource: OperatorResourceInfo, eth_tx: EthTx):
        self._eth_tx = eth_tx
        self._neon_sig = '0x' + eth_tx.hash_signed().hex()
        self._solana = solana
        self._resource = resource
        self._builder = NeonIxBuilder(resource.public_key)
        self._account_tx_list_builder = AccountTxListBuilder(solana, self._builder)

        self._builder.init_operator_ether(self._resource.ether)
        self._builder.init_eth_tx(self._eth_tx)
        self._builder.init_iterative(self._resource.storage, self._resource.holder, self._resource.rid)

        self._alt_close_queue = AddressLookupTableCloseQueue(self._solana)

    @property
    def neon_sig(self) -> str:
        return self._neon_sig

    @property
    def eth_tx(self) -> EthTx:
        return self._eth_tx

    @property
    def resource(self) -> OperatorResourceInfo:
        return self._resource

    @property
    def builder(self) -> NeonIxBuilder:
        return self._builder

    @property
    def solana(self) -> SolanaInteractor:
        return self._solana

    @property
    def account_tx_list_builder(self) -> AccountTxListBuilder:
        return self._account_tx_list_builder

    @property
    def alt_close_queue(self) -> AddressLookupTableCloseQueue:
        return self._alt_close_queue


@logged_group("neon.Proxy")
class BaseNeonTxStrategy(abc.ABC):
    NAME = 'UNKNOWN STRATEGY'

    def __init__(self, precheck_res: NeonTxPrecheckResult, ctx: NeonTxSendCtx):
        self._precheck_res = precheck_res
        self._error_msg: Optional[str] = None
        self._ctx = ctx
        self._iter_evm_step_cnt = EVM_STEP_COUNT
        self._is_valid = self._validate()

    @property
    def _account_tx_list_builder(self) -> AccountTxListBuilder:
        return self._ctx.account_tx_list_builder

    @property
    def _alt_close_queue(self) -> AddressLookupTableCloseQueue:
        return self._ctx.alt_close_queue

    @property
    def _builder(self) -> NeonIxBuilder:
        return self._ctx.builder

    @property
    def _solana(self) -> SolanaInteractor:
        return self._ctx.solana

    @property
    def _signer(self) -> SolanaAccount:
        return self._ctx.resource.signer

    @property
    def neon_sig(self) -> str:
        return self._ctx.neon_sig

    def is_valid(self) -> bool:
        return self._is_valid

    @property
    def error_msg(self) -> str:
        assert self._error_msg is not None
        return cast(str, self._error_msg)

    @abc.abstractmethod
    def build_tx(self, idx=0) -> Transaction:
        return TransactionWithComputeBudget()

    def build_cancel_tx(self) -> Transaction:
        return TransactionWithComputeBudget().add(self._builder.make_cancel_instruction())

    def _build_prep_tx_list(self) -> Tuple[str, List[Transaction]]:
        tx_list_name = self._account_tx_list_builder.name
        tx_list = self._account_tx_list_builder.get_tx_list()

        alt_tx_list = self._alt_close_queue.pop_tx_list(self._signer.public_key())
        if len(alt_tx_list):
            tx_list.extend(alt_tx_list)
            tx_list_name = ' + '.join([tx_list_name, f'CloseLookupTable({len(alt_tx_list)})'])

        return tx_list_name, tx_list

    def _execute_prep_tx_list(self, waiter: IConfirmWaiter) -> List[str]:
        tx_list_name, tx_list = self._build_prep_tx_list()
        if not len(tx_list):
            return []

        tx_sender = SolTxListSender(self._solana, self._signer)
        tx_sender.send(tx_list_name, tx_list, waiter=waiter)
        self._account_tx_list_builder.clear_tx_list()
        return tx_sender.success_sig_list

    def _build_tx_list(self, cnt: int) -> Tuple[str, List[Transaction]]:
        tx_list = [self.build_tx(i) for i in range(cnt)]
        return f'{self.NAME}({cnt})', tx_list

    @abc.abstractmethod
    def _execute_tx_list(self, waiter: IConfirmWaiter) -> Tuple[NeonTxResultInfo, List[str]]:
        waiter.on_wait_confirm(0, 0, False)
        return NeonTxResultInfo(), []

    def execute(self, waiter: IConfirmWaiter) -> Tuple[NeonTxResultInfo, List[str]]:
        assert self.is_valid()
        self._execute_prep_tx_list(waiter)
        return self._execute_tx_list(waiter)

    @abc.abstractmethod
    def _validate(self) -> bool:
        return True

    @abc.abstractmethod
    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        return []

    def _validate_notdeploy_tx(self) -> bool:
        if len(self._ctx.eth_tx.toAddress) == 0:
            self._error_msg = 'Deploy transaction'
            return False
        return True

    def _validate_tx_size(self) -> bool:
        tx = self.build_tx(1)
        # Predefined blockhash is used only to check transaction size, the transaction won't be sent to network
        tx.recent_blockhash = Blockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        tx.sign(self._signer)
        try:
            tx.serialize()
            return True
        except Exception as err:
            if SolReceiptParser(err).check_if_big_transaction():
                self._error_msg = 'Too big transaction size'
                return False
            self._error_msg = str(err)
            raise

    def _validate_tx_wo_chainid(self) -> bool:
        if not self._precheck_res.is_underpriced_tx_without_chainid:
            return True

        self._error_msg = "Underpriced transaction without chain-id"
        return False


class SimpleNeonTxSender(SolTxListSender):
    def __init__(self, strategy: BaseNeonTxStrategy, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._strategy = strategy
        self.neon_res = NeonTxResultInfo()

    def _on_success_send(self, tx: Transaction, receipt: {}) -> None:
        if not self.neon_res.is_valid():
            self.neon_res.decode(self._strategy.neon_sig, receipt).is_valid()
        super()._on_success_send(tx, receipt)

    def _on_post_send(self) -> None:
        if self.neon_res.is_valid():
            self.debug(f'Got Neon tx result: {self.neon_res}')
            self.clear()
        else:
            super()._on_post_send()

            if not len(self._tx_list):
                raise RuntimeError('Run out of attempts to execute transaction')


class SimpleNeonTxStrategy(BaseNeonTxStrategy):
    NAME = 'CallFromRawEthereumTX'
    IS_SIMPLE = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _validate(self) -> bool:
        return (
            self._validate_evm_step_cnt() and
            self._validate_notdeploy_tx() and
            self._validate_tx_wo_chainid() and
            self._validate_tx_size()
        )

    def _validate_evm_step_cnt(self) -> bool:
        emulated_evm_step_cnt = self._precheck_res.emulating_result["steps_executed"]
        if emulated_evm_step_cnt > self._iter_evm_step_cnt:
            self._error_msg = 'Too big number of EVM steps'
            return False
        return True

    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        raise NotImplementedError("Simple strategy doesn't know anything about iterations")

    def build_tx(self, _=0) -> Transaction:
        tx = TransactionWithComputeBudget()
        tx.add(self._builder.make_noniterative_call_transaction(len(tx.instructions)))
        return tx

    def _execute_tx_list(self, waiter: IConfirmWaiter) -> Tuple[NeonTxResultInfo, List[str]]:
        tx_sender = SimpleNeonTxSender(self, self._solana, self._signer)
        tx_sender.send(self.NAME, [self.build_tx()], waiter=waiter)
        if not tx_sender.neon_res.is_valid():
            raise tx_sender.raise_budget_exceeded()
        return tx_sender.neon_res, tx_sender.success_sig_list


class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_canceled = False
        self._postponed_exception: Optional[Exception] = None

    def _try_lock_accounts(self) -> None:
        time.sleep(self.ONE_BLOCK_TIME)  # one block time

        # send one transaction to get lock, and only after that send all others
        tx = self._blocked_account_list.pop()
        self._set_tx_blockhash(tx)
        self._tx_list = [tx]

        # prevent the transaction sending one at a time
        self._pending_list += self._blocked_account_list
        self._blocked_account_list.clear()

    def _cancel(self) -> None:
        self.debug(f'Cancel the transaction')
        self.clear()
        self._name = 'CancelWithNonce'
        self._is_canceled = True
        self._retry_idx = 0  # force the cancel sending
        self._tx_list = [self._strategy.build_cancel_tx()]

    def _decrease_iter_evm_step_cnt(self):
        tx_list = self._strategy.decrease_iter_evm_step_cnt(self._get_full_tx_list())
        if not len(tx_list):
            return self._cancel()
        self.clear()
        self._tx_list = tx_list

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
        if self._unknown_error_receipt is not None:
            self._set_postponed_exception(SolTxError(self._unknown_error_receipt))
            if self._is_canceled:
                self._raise_error()

            self._unknown_error_list.clear()
            self._unknown_error_receipt = None
            if len(self.success_sig_list):
                return self._cancel()
            self._raise_error()

        # There is no more retries to send transactions
        if self._retry_idx >= RETRY_ON_FAIL:
            self._set_postponed_exception(EthereumError(message='No more retries to complete transaction!'))
            if (not self._is_canceled) and len(self.success_sig_list):
                return self._cancel()
            self._raise_error()

        # Blockhash is changed (((
        if len(self._bad_block_list):
            self._blockhash = None

        # Address Lookup Tables can't be used in the same block with extending of it
        if len(self._alt_invalid_index_list):
            time.sleep(self.ONE_BLOCK_TIME)
        # Accounts are blocked, so try to lock them
        elif len(self._blocked_account_list):
            return self._try_lock_accounts()

        # Compute budged is exceeded, so decrease EVM steps per iteration
        if len(self._budget_exceeded_list):
            return self._decrease_iter_evm_step_cnt()

        self._move_tx_list()

        # if no iterations and no result then add the additional iteration
        if not len(self._tx_list):
            self.debug('No result -> add the additional iteration')
            self._tx_list.append(self._strategy.build_tx())


class IterativeNeonTxStrategy(BaseNeonTxStrategy):
    NAME = 'PartialCallOrContinueFromRawEthereumTX'
    IS_SIMPLE = False

    def __init__(self, *args, **kwargs):
        self._compute_unit_cnt: Optional[int] = None
        super().__init__(*args, **kwargs)

    def _validate(self) -> bool:
        return (
            self._validate_notdeploy_tx() and
            self._validate_tx_size() and
            self._validate_evm_step_cnt() and
            self._validate_tx_wo_chainid()
        )

    def _validate_evm_step_cnt(self):
        # Only the instruction with a holder account allows to pass a unique number to make the transaction unique
        emulated_evm_step_cnt = self._precheck_res.emulating_result["steps_executed"]
        max_evm_step_cnt = self._iter_evm_step_cnt * 25
        if emulated_evm_step_cnt > max_evm_step_cnt:
            self._error_msg = 'Big number of EVM steps'
            return False
        return True

    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        if self._iter_evm_step_cnt <= 10:
            return []

        prev_total_iteration_cnt = len(tx_list)
        evm_step_cnt = self._iter_evm_step_cnt
        prev_evm_step_cnt = evm_step_cnt
        total_evm_step_cnt = prev_total_iteration_cnt * evm_step_cnt

        if evm_step_cnt > 170:
            evm_step_cnt -= 150
        else:
            self._compute_unit_cnt = 1_300_000
            evm_step_cnt = 10
        self._iter_evm_step_cnt = evm_step_cnt
        total_iteration_cnt = math.ceil(total_evm_step_cnt / evm_step_cnt)

        self.debug(
            f'Decrease EVM steps from {prev_evm_step_cnt} to {evm_step_cnt}, ' +
            f'iterations increase from {prev_total_iteration_cnt} to {total_iteration_cnt}'
        )

        return [self.build_tx(idx) for idx in range(total_iteration_cnt)]

    def build_tx(self, idx=0) -> Transaction:
        tx = TransactionWithComputeBudget(compute_units=self._compute_unit_cnt)
        # generate unique tx
        evm_step_cnt = self._iter_evm_step_cnt + idx
        tx.add(self._builder.make_partial_call_or_continue_transaction(evm_step_cnt, len(tx.instructions)))
        return tx

    def _calc_iter_cnt(self) -> int:
        emulated_evm_step_cnt = self._precheck_res.emulating_result["steps_executed"]
        iter_cnt = math.ceil(emulated_evm_step_cnt / self._iter_evm_step_cnt)
        iter_cnt = math.ceil(emulated_evm_step_cnt / (self._iter_evm_step_cnt - iter_cnt))
        if emulated_evm_step_cnt > 200:
            iter_cnt += 2  # +1 on begin, +1 on end
        return iter_cnt

    def _execute_tx_list(self, waiter: IConfirmWaiter) -> Tuple[NeonTxResultInfo, List[str]]:
        emulated_evm_step_cnt = self._precheck_res.emulating_result["steps_executed"]
        iter_cnt = self._calc_iter_cnt()
        self.debug(f'Total iterations {iter_cnt} for {emulated_evm_step_cnt} ({self._iter_evm_step_cnt}) EVM steps')

        tx_list_name, tx_list = self._build_tx_list(iter_cnt)
        tx_sender = IterativeNeonTxSender(self, self._solana, self._signer)
        tx_sender.send(tx_list_name, tx_list, waiter=waiter)
        return tx_sender.neon_res, tx_sender.success_sig_list


class HolderNeonTxStrategy(IterativeNeonTxStrategy):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _validate(self) -> bool:
        return (
            self._validate_tx_size() and
            self._validate_tx_wo_chainid()
        )

    def build_tx(self, idx=0) -> Transaction:
        evm_step_cnt = self._iter_evm_step_cnt
        return TransactionWithComputeBudget(compute_units=self._compute_unit_cnt).add(
            self._builder.make_partial_call_or_continue_from_account_data_instruction(evm_step_cnt, idx)
        )

    def _calc_iter_cnt(self) -> int:
        emulated_evm_step_cnt = self._precheck_res.emulating_result["steps_executed"]
        return math.ceil(emulated_evm_step_cnt / self._iter_evm_step_cnt) + 1

    def _build_prep_tx_list(self) -> Tuple[str, List[Transaction]]:
        tx_list_name, tx_list = super()._build_prep_tx_list()

        # write eth transaction to the holder account
        cnt = 0
        holder_msg_offset = 0
        holder_msg = copy.copy(self._builder.holder_msg)
        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = TransactionWithComputeBudget().add(
                self._builder.make_write_instruction(holder_msg_offset, holder_msg_part)
            )
            tx_list.append(tx)
            holder_msg_offset += len(holder_msg_part)
            cnt += 1

        tx_list_name = ' + '.join([tx_list_name, f'WriteWithHolder({cnt})'])
        return tx_list_name, tx_list


class AltHolderNeonTxStrategy(HolderNeonTxStrategy):
    NAME = 'AltExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs):
        self._alt_builder: Optional[AddressLookupTableTxBuilder] = None
        self._alt_info: Optional[AddressLookupTableInfo] = None
        self._alt_tx_list: Optional[AddressLookupTableTxList] = None
        super().__init__(*args, **kwargs)

    def _validate(self) -> bool:
        return (
            self._validate_tx_wo_chainid() and
            self._build_alt_info() and
            self._validate_tx_size()
        )

    def _build_legacy_tx(self, idx=0) -> Transaction:
        return super().build_tx(idx)

    def _build_legacy_cancel_tx(self) -> Transaction:
        return super().build_cancel_tx()

    def _build_alt_info(self) -> bool:
        legacy_tx = self._build_legacy_tx()
        try:
            alt_builder = AddressLookupTableTxBuilder(self._solana, self._builder, self._signer, self._alt_close_queue)
            self._alt_builder = alt_builder
            self._alt_info = alt_builder.build_alt_info(legacy_tx)
        except Exception as e:
            self._error_msg = str(e)
            return False
        return True

    def build_tx(self, idx=0) -> Transaction:
        legacy_tx = self._build_legacy_tx(idx)
        return V0Transaction(address_table_lookups=[self._alt_info]).add(legacy_tx)

    def build_cancel_tx(self) -> Transaction:
        legacy_tx = self._build_legacy_cancel_tx()
        return V0Transaction(address_table_lookups=[self._alt_info]).add(legacy_tx)

    def _execute_prep_tx_list(self, waiter: IConfirmWaiter) -> List[str]:
        tx_list_name, tx_list = super()._build_prep_tx_list()

        self._alt_tx_list = self._alt_builder.build_alt_tx_list(self._alt_info)
        sig_list = self._alt_builder.prep_alt_list(self._alt_tx_list, tx_list_name, tx_list, waiter)
        self._alt_builder.update_alt_info_list([self._alt_info])

        return sig_list

    def execute(self, waiter: IConfirmWaiter) -> Tuple[NeonTxResultInfo, List[str]]:
        try:
            return super().execute(waiter)
        finally:
            if (self._alt_tx_list is not None) and (len(self._alt_tx_list) > 0):
                self._alt_builder.done_alt_list(self._alt_tx_list)


class BaseNoChainIdNeonStrategy:
    @staticmethod
    def validate(precheck_res: NeonTxPrecheckResult) -> bool:
        return precheck_res.is_underpriced_tx_without_chainid

    @staticmethod
    def build_tx(builder: NeonIxBuilder, compute_unit_cnt: Optional[int], evm_step_cnt: int, idx: int) -> Transaction:
        return TransactionWithComputeBudget(compute_units=compute_unit_cnt).add(
            builder.make_partial_call_or_continue_from_account_data_no_chainid_instruction(evm_step_cnt, idx)
        )


class NoChainIdNeonTxStrategy(HolderNeonTxStrategy):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _validate(self) -> bool:
        if not BaseNoChainIdNeonStrategy.validate(self._precheck_res):
            self._error_msg = 'Normal transaction'
            return False

        return self._validate_tx_size()

    def build_tx(self, idx=0) -> Transaction:
        return BaseNoChainIdNeonStrategy.build_tx(self._builder, self._compute_unit_cnt, self._iter_evm_step_cnt, idx)


class AltNoChainIdNeonTxStrategy(AltHolderNeonTxStrategy):
    NAME = 'AltExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _validate(self) -> bool:
        if not BaseNoChainIdNeonStrategy.validate(self._precheck_res):
            self._error_msg = 'Normal transaction'
            return False

        return self._validate_tx_size()

    def _build_legacy_tx(self, idx=0) -> Transaction:
        return BaseNoChainIdNeonStrategy.build_tx(self._builder, self._compute_unit_cnt, self._iter_evm_step_cnt, idx)


@logged_group("neon.Proxy")
class NeonTxSendStrategySelector(IConfirmWaiter):
    STRATEGY_LIST = [
        SimpleNeonTxStrategy,
        IterativeNeonTxStrategy, HolderNeonTxStrategy, AltHolderNeonTxStrategy,
        NoChainIdNeonTxStrategy, AltNoChainIdNeonTxStrategy
    ]

    def __init__(self, db: MemDB, solana: SolanaInteractor, resource: OperatorResourceInfo, eth_tx: EthTx):
        super().__init__()
        self._db = db
        self._ctx = NeonTxSendCtx(solana, resource, eth_tx)
        self._operator = f'{str(self._ctx.resource)}'
        self._pending_tx: Optional[NeonPendingTxInfo] = None

    def execute(self, precheck_result: NeonTxPrecheckResult) -> NeonTxResultInfo:
        self._validate_pend_tx()
        self._ctx.account_tx_list_builder.build_tx(precheck_result.emulating_result)
        return self._execute(precheck_result)

    def _validate_pend_tx(self) -> None:
        self._pending_tx = NeonPendingTxInfo(neon_sign=self._ctx.neon_sig, operator=self._operator, slot=0)
        self._pend_tx_into_db(self._ctx.solana.get_recent_blockslot())

    def _execute(self, precheck_result: NeonTxPrecheckResult) -> NeonTxResultInfo:
        for Strategy in self.STRATEGY_LIST:
            try:
                strategy = Strategy(precheck_result, self._ctx)
                if not strategy.is_valid():
                    self.debug(f'Skip strategy {Strategy.NAME}: {strategy.error_msg}')
                    continue

                self.debug(f'Use strategy {Strategy.NAME}')
                neon_res, sig_list = strategy.execute(waiter=self)
                self._submit_tx_into_db(neon_res, sig_list)
                return neon_res
            except Exception as e:
                if (not Strategy.IS_SIMPLE) or (not SolReceiptParser(e).check_if_budget_exceeded()):
                    raise

        self.error(f'No strategy to execute the Neon transaction: {self._ctx.eth_tx}')
        raise EthereumError(message="transaction is too big for execution")

    def on_wait_confirm(self, _: int, block_slot: int, __: bool) -> None:
        self._pend_tx_into_db(block_slot)

    def _pend_tx_into_db(self, block_slot: int):
        """
        Transaction sender doesn't remove pending transactions!!!
        This protects the neon transaction execution from race conditions, when user tries to send transaction
        multiple time. User can send the same transaction after it complete too.

        Indexer will purge old pending transactions after finalizing slot.
        """
        if self._pending_tx and ((block_slot - self._pending_tx.slot) > 10):
            self.debug(f'Set pending transaction: diff {block_slot - self._pending_tx.slot}, set {block_slot}')
            self._pending_tx.slot = block_slot
            self._db.pend_transaction(self._pending_tx)

    def _submit_tx_into_db(self, neon_res: NeonTxResultInfo, sig_list: List[str]):
        neon_tx = NeonTxInfo()
        neon_tx.init_from_eth_tx(self._ctx.eth_tx)
        self._db.submit_transaction(neon_tx, neon_res, sig_list)
