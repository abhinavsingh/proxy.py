from __future__ import annotations

import abc
import math
import time
import copy

from logged_groups import logged_group
from typing import Dict, Optional, List, Any, cast

from solana.transaction import AccountMeta as SolanaAccountMeta, Transaction, PublicKey
from solana.blockhash import Blockhash
from solana.account import Account as SolanaAccount

from .neon_tx_stages import NeonTxStage, NeonCreateAccountTxStage, NeonCreateERC20TxStage, NeonCreateContractTxStage
from .neon_tx_stages import NeonResizeContractTxStage

from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.emulator_interactor import call_trx_emulated
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.errors import BlockedAccountsError, NodeBehindError, SolanaUnavailableError
from ..common_neon.solana_tx_list_sender import SolTxListInfo, SolTxListSender
from ..common_neon.solana_receipt_parser import SolTxError, SolReceiptParser
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxReceiptInfo
from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.utils import NeonTxResultInfo
from ..common_neon.data import NeonTxExecCfg, NeonAccountDict, NeonEmulatedResult
from ..common_neon.environment_data import RETRY_ON_FAIL, EVM_STEP_COUNT
from ..common_neon.elf_params import ElfParams
from ..common_neon.evm_log_decoder import decode_neon_tx_result

from ..common_neon.solana_alt import AddressLookupTableInfo
from ..common_neon.solana_alt_builder import AddressLookupTableTxBuilder, AddressLookupTableTxSet
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue
from ..common_neon.solana_v0_transaction import V0Transaction

from .operator_resource_list import OperatorResourceInfo


@logged_group("neon.MemPool")
class AccountTxListBuilder:
    def __init__(self, solana: SolanaInteractor, builder: NeonIxBuilder):
        self._solana = solana
        self._builder = builder
        self._resize_contract_stage_list: List[NeonTxStage] = []
        self._create_account_stage_list: List[NeonTxStage] = []
        self._eth_meta_dict: Dict[str, SolanaAccountMeta] = dict()

    def build_tx(self, emulated_account_dict: NeonAccountDict) -> None:
        self._resize_contract_stage_list.clear()
        self._create_account_stage_list.clear()
        self._eth_meta_dict.clear()

        # Parse information from the emulator output
        self._parse_accounts_list(emulated_account_dict['accounts'])
        self._parse_token_list(emulated_account_dict['token_accounts'])
        self._parse_solana_list(emulated_account_dict['solana_accounts'])

        eth_meta_list = list(self._eth_meta_dict.values())
        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in eth_meta_list]))
        self._builder.init_eth_accounts(eth_meta_list)

        # Build all instructions
        self._build_account_stage_list()

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
                    self._create_account_stage_list.append(stage)
                elif account_desc['writable']:
                    stage = NeonCreateAccountTxStage(self._builder, account_desc)
                    self._create_account_stage_list.append(stage)
            elif account_desc['code_size'] and (account_desc['code_size_current'] < account_desc['code_size']):
                self._resize_contract_stage_list.append(NeonResizeContractTxStage(self._builder, account_desc))

            self._add_meta(account_desc['account'], True)
            if account_desc['contract']:
                self._add_meta(account_desc['contract'], account_desc['writable'])

    def _parse_token_list(self, emulated_result_token_accounts: List[Dict[str, Any]]) -> None:
        for token_account in emulated_result_token_accounts:
            self._add_meta(token_account['key'], True)
            if token_account['new']:
                self._create_account_stage_list.append(NeonCreateERC20TxStage(self._builder, token_account))

    def _parse_solana_list(self, emulated_result_solana_account_list: List[Dict[str, Any]]) -> None:
        for account_desc in emulated_result_solana_account_list:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

    def _build_account_stage_list(self) -> None:
        if not self.has_tx_list():
            return

        all_stage_list = self._create_account_stage_list + self._resize_contract_stage_list
        size_list = list(set([s.size for s in all_stage_list]))
        balance_list = self._solana.get_multiple_rent_exempt_balances_for_size(size_list)
        balance_map = {size: balance for size, balance in zip(size_list, balance_list)}
        for s in all_stage_list:
            s.set_balance(balance_map[s.size])
            s.build()

    def has_tx_list(self) -> bool:
        return len(self._resize_contract_stage_list) > 0 or len(self._create_account_stage_list) > 0

    def get_tx_list_info(self) -> SolTxListInfo:
        all_stage_list = self._create_account_stage_list + self._resize_contract_stage_list

        return SolTxListInfo(
            name_list=[s.NAME for s in all_stage_list],
            tx_list=[s.tx for s in all_stage_list]
        )

    def clear_tx_list(self) -> None:
        self._resize_contract_stage_list.clear()
        self._create_account_stage_list.clear()


class NeonTxSendCtx:
    def __init__(self, solana: SolanaInteractor, resource: OperatorResourceInfo, neon_tx: NeonTx):
        self._neon_tx = neon_tx
        self._neon_sig = '0x' + neon_tx.hash_signed().hex()
        self._solana = solana
        self._resource = resource
        self._builder = NeonIxBuilder(resource.public_key)

        self._account_tx_list_builder = AccountTxListBuilder(solana, self._builder)
        self._emulated_evm_step_cnt = 0

        self._builder.init_operator_ether(self._resource.ether)
        self._builder.init_eth_tx(self._neon_tx)
        self._builder.init_iterative(self._resource.storage, self._resource.holder, self._resource.rid)

        self._alt_close_queue = AddressLookupTableCloseQueue(self._solana)

        self._is_holder_completed = False

    @property
    def neon_sig(self) -> str:
        return self._neon_sig

    @property
    def neon_tx(self) -> NeonTx:
        return self._neon_tx

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

    @property
    def emulated_evm_step_cnt(self) -> int:
        assert self._emulated_evm_step_cnt >= 0
        return self._emulated_evm_step_cnt

    def set_emulated_evm_step_cnt(self, value: int) -> None:
        assert value >= 0
        self._emulated_evm_step_cnt = value

    @property
    def is_holder_completed(self):
        return self._is_holder_completed

    def set_holder_completed(self, value=True) -> None:
        self._is_holder_completed = value


@logged_group("neon.MemPool")
class BaseNeonTxStrategy(abc.ABC):
    NAME = 'UNKNOWN STRATEGY'

    def __init__(self, ctx: NeonTxSendCtx):
        self._validation_error_msg: Optional[str] = None
        self._ctx = ctx
        self._iter_evm_step_cnt = EVM_STEP_COUNT

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
    def _neon_tx(self) -> NeonTx:
        return self._ctx.neon_tx

    @property
    def neon_sig(self) -> str:
        return self._ctx.neon_sig

    @property
    def validation_error_msg(self) -> str:
        assert not self.is_valid()
        return cast(str, self._validation_error_msg)

    def is_valid(self) -> bool:
        return self._validation_error_msg is None

    @abc.abstractmethod
    def validate(self) -> bool:
        self._validation_error_msg = 'Not implemented'
        return False

    def _validate_notdeploy_tx(self) -> bool:
        if len(self._ctx.neon_tx.toAddress) == 0:
            self._validation_error_msg = 'Deploy transaction'
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
                self._validation_error_msg = 'Too big transaction size'
                return False
            self._validation_error_msg = str(err)
            raise

    def _validate_tx_has_chainid(self) -> bool:
        if self._neon_tx.hasChainId():
            return True

        self._validation_error_msg = "Transaction without chain-id"
        return False

    @abc.abstractmethod
    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        pass

    def _execute_prep_tx_list(self, tx_list_info_list: List[SolTxListInfo]) -> None:
        assert self.is_valid()
        tx_sender = SolTxListSender(self._solana, self._signer)
        for tx_list_info in tx_list_info_list:
            tx_sender.send(tx_list_info)

    def _build_prep_tx_list_before_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()
        return []

    def prep_before_emulate(self) -> bool:
        assert self.is_valid()
        tx_list_info_list = self._build_prep_tx_list_before_emulate()
        if len(tx_list_info_list) == 0:
            return False
        self._execute_prep_tx_list(tx_list_info_list)
        return True

    def _build_prep_tx_list_after_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()
        tx_list_info = self._account_tx_list_builder.get_tx_list_info()

        alt_tx_list = self._alt_close_queue.pop_tx_list(self._signer.public_key())
        if len(alt_tx_list):
            tx_list_info.tx_list.extend(alt_tx_list)
            tx_list_info.name_list.extend(['CloseLookupTable' for _ in alt_tx_list])

        if len(tx_list_info.tx_list) == 0:
            return []
        return [tx_list_info]

    def prep_after_emulate(self) -> bool:
        assert self.is_valid()
        tx_list_info_list = self._build_prep_tx_list_after_emulate()
        if len(tx_list_info_list) == 0:
            return False
        self._execute_prep_tx_list(tx_list_info_list)
        self._account_tx_list_builder.clear_tx_list()
        return True

    @abc.abstractmethod
    def build_tx(self, idx=0) -> Transaction:
        return TransactionWithComputeBudget()

    def build_cancel_tx(self) -> Transaction:
        return TransactionWithComputeBudget().add(self._builder.make_cancel_instruction())

    def _build_tx_list(self, cnt: int) -> SolTxListInfo:
        return SolTxListInfo(
            tx_list=[self.build_tx(i) for i in range(cnt)],
            name_list=[self.NAME for _ in range(cnt)]
        )

    @abc.abstractmethod
    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()
        return NeonTxResultInfo()


@logged_group("neon.MemPool")
class SimpleNeonTxSender(SolTxListSender):
    def __init__(self, strategy: BaseNeonTxStrategy, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._strategy = strategy
        self.neon_tx_res = NeonTxResultInfo()

    def _decode_neon_tx_result(self, sol_receipt: Dict[str, Any]) -> None:
        if self.neon_tx_res.is_valid():
            return

        block_slot = sol_receipt['slot']
        sol_sig = sol_receipt['transaction']['signatures'][0]
        sol_tx = SolTxReceiptInfo(SolTxMetaInfo(block_slot, sol_sig, sol_receipt))
        for sol_neon_ix in sol_tx.iter_sol_neon_ix():
            if decode_neon_tx_result(sol_neon_ix.iter_log(), self._strategy.neon_sig, self.neon_tx_res):
                break

    def _on_success_send(self, sol_tx: Transaction, sol_receipt: Dict[str, Any]) -> None:
        self._decode_neon_tx_result(sol_receipt)
        super()._on_success_send(sol_tx, sol_receipt)

    def _on_post_send(self) -> None:
        if self.neon_tx_res.is_valid():
            self.debug(f'Got Neon tx result: {self.neon_tx_res}')
            self.clear()
        else:
            super()._on_post_send()
            if not len(self._tx_list):
                raise RuntimeError('Run out of attempts to execute transaction')


@logged_group("neon.MemPool")
class SimpleNeonTxStrategy(BaseNeonTxStrategy):
    NAME = 'CallFromRawEthereumTX'
    IS_SIMPLE = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def decrease_iter_evm_step_cnt(self, tx_list: List[Transaction]) -> List[Transaction]:
        raise NotImplementedError(f"{self.NAME} strategy doesn't know anything about iterations")

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_evm_step_cnt() and
            self._validate_notdeploy_tx() and
            self._validate_tx_has_chainid() and
            self._validate_tx_size()
        )

    def _validate_evm_step_cnt(self) -> bool:
        if self._ctx.emulated_evm_step_cnt > self._iter_evm_step_cnt:
            self._validation_error_msg = 'Too big number of EVM steps'
            return False
        return True

    def build_tx(self, _=0) -> Transaction:
        tx = TransactionWithComputeBudget()
        tx.add(self._builder.make_noniterative_call_transaction(len(tx.instructions)))
        return tx

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()
        tx_list_info = SolTxListInfo([self.NAME], [self.build_tx()])

        tx_sender = SimpleNeonTxSender(self, self._solana, self._signer)
        tx_sender.send(tx_list_info)
        if not tx_sender.neon_tx_res.is_valid():
            raise tx_sender.raise_budget_exceeded()
        return tx_sender.neon_tx_res


@logged_group("neon.MemPool")
class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_canceled = False
        self._postponed_exception: Optional[Exception] = None

    def _cancel(self) -> None:
        self.debug(f'Cancel the transaction')
        self.clear()
        self._name = 'CancelWithNonce'
        self._is_canceled = True
        self._retry_idx = 0  # force the cancel sending
        self._tx_list = [self._strategy.build_cancel_tx()]

    def _decrease_iter_evm_step_cnt(self) -> None:
        tx_list = self._strategy.decrease_iter_evm_step_cnt(self._get_full_tx_list())
        if not len(tx_list):
            return self._cancel()
        self.clear()
        self._tx_list = tx_list

    def _on_success_send(self, sol_tx: Transaction, sol_receipt: {}) -> None:
        if self._is_canceled:
            # Transaction with cancel is confirmed
            self.neon_tx_res.fill_result(status="0x0", gas_used='0x0', return_value='')
        else:
            super()._on_success_send(sol_tx, sol_receipt)

    def _set_postponed_exception(self, exception: Exception) -> None:
        if not self._postponed_exception:
            self._postponed_exception = exception

    def _raise_error(self) -> None:
        assert self._postponed_exception is not None
        raise self._postponed_exception

    def _on_post_send(self) -> None:
        # Result is received
        if self.neon_tx_res.is_valid():
            self.debug(f'Got Neon tx {"cancel" if self._is_canceled else "result"}: {self.neon_tx_res}')
            if self._is_canceled and self._postponed_exception:
                self._raise_error()
            return self.clear()

        if len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            raise NodeBehindError()

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
            self._set_postponed_exception(RuntimeError('No more retries to complete transaction!'))
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
            raise BlockedAccountsError()

        # Compute budged is exceeded, so decrease EVM steps per iteration
        if len(self._budget_exceeded_list):
            return self._decrease_iter_evm_step_cnt()

        self._move_tx_list()

        # if no iterations and no result then add the additional iteration
        if not len(self._tx_list):
            self.debug('No result -> add the additional iteration')
            self._tx_list.append(self._strategy.build_tx())


@logged_group("neon.MemPool")
class IterativeNeonTxStrategy(BaseNeonTxStrategy):
    NAME = 'PartialCallOrContinueFromRawEthereumTX'
    IS_SIMPLE = False

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._compute_unit_cnt: Optional[int] = None

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_notdeploy_tx() and
            self._validate_tx_size() and
            self._validate_evm_step_cnt() and
            self._validate_tx_has_chainid()
        )

    def _validate_evm_step_cnt(self) -> bool:
        # Only the instruction with a holder account allows to pass a unique number to make the transaction unique
        emulated_evm_step_cnt = self._ctx.emulated_evm_step_cnt
        max_evm_step_cnt = self._iter_evm_step_cnt * 25
        if emulated_evm_step_cnt > max_evm_step_cnt:
            self._validation_error_msg = 'Big number of EVM steps'
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
            self._compute_unit_cnt = 1_350_000
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
        iter_cnt = math.ceil(self._ctx.emulated_evm_step_cnt / self._iter_evm_step_cnt)
        iter_cnt = math.ceil(self._ctx.emulated_evm_step_cnt / (self._iter_evm_step_cnt - iter_cnt))
        return iter_cnt

    def execute(self) -> NeonTxResultInfo:
        assert self.is_valid()
        emulated_evm_step_cnt = self._ctx.emulated_evm_step_cnt
        iter_cnt = self._calc_iter_cnt()
        self.debug(f'Total iterations {iter_cnt} for {emulated_evm_step_cnt} ({self._iter_evm_step_cnt}) EVM steps')

        tx_list_info = self._build_tx_list(iter_cnt)
        tx_sender = IterativeNeonTxSender(self, self._solana, self._signer)
        tx_sender.send(tx_list_info)
        return tx_sender.neon_tx_res


@logged_group("neon.MemPool")
class HolderNeonTxStrategy(IterativeNeonTxStrategy):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_tx_size() and
            self._validate_tx_has_chainid()
        )

    def build_tx(self, idx=0) -> Transaction:
        evm_step_cnt = self._iter_evm_step_cnt
        return TransactionWithComputeBudget(compute_units=self._compute_unit_cnt).add(
            self._builder.make_partial_call_or_continue_from_account_data_instruction(evm_step_cnt, idx)
        )

    def _calc_iter_cnt(self) -> int:
        return math.ceil(self._ctx.emulated_evm_step_cnt / self._iter_evm_step_cnt) + 1

    def _build_prep_tx_list_before_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()

        if self._ctx.is_holder_completed:
            return []

        # write eth transaction to the holder account
        tx_list_info = SolTxListInfo([], [])
        holder_msg_offset = 0
        holder_msg = copy.copy(self._builder.holder_msg)
        holder_msg_size = ElfParams().holder_msg_size
        while len(holder_msg):
            (holder_msg_part, holder_msg) = (holder_msg[:holder_msg_size], holder_msg[holder_msg_size:])
            tx = TransactionWithComputeBudget().add(
                self._builder.make_write_instruction(holder_msg_offset, holder_msg_part)
            )
            tx_list_info.name_list.append('WriteWithHolder')
            tx_list_info.tx_list.append(tx)
            holder_msg_offset += holder_msg_size

        self._ctx.set_holder_completed()
        return [tx_list_info]


@logged_group("neon.MemPool")
class AltHolderNeonTxStrategy(HolderNeonTxStrategy):
    NAME = 'AltExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._alt_builder: Optional[AddressLookupTableTxBuilder] = None
        self._alt_info: Optional[AddressLookupTableInfo] = None
        self._alt_tx_set: Optional[AddressLookupTableTxSet] = None

    def validate(self) -> bool:
        self._validation_error_msg = None
        return (
            self._validate_tx_has_chainid() and
            self._init_alt_info() and
            self._validate_tx_size()
        )

    def _build_legacy_tx(self, idx=0) -> Transaction:
        return super().build_tx(idx)

    def _build_legacy_cancel_tx(self) -> Transaction:
        return super().build_cancel_tx()

    def _init_alt_info(self) -> bool:
        # TODO: if there are a lot of changes in the account list, the alt should be regenerated
        if self._alt_info is not None:
            return True

        legacy_tx = self._build_legacy_tx()
        try:
            alt_builder = AddressLookupTableTxBuilder(self._solana, self._builder, self._signer, self._alt_close_queue)
            self._alt_info = alt_builder.build_alt_info(legacy_tx)
            self._alt_builder = alt_builder
        except Exception as e:
            self._validation_error_msg = str(e)
            return False
        return True

    def build_tx(self, idx=0) -> Transaction:
        legacy_tx = self._build_legacy_tx(idx)
        return V0Transaction(address_table_lookups=[self._alt_info]).add(legacy_tx)

    def build_cancel_tx(self) -> Transaction:
        legacy_tx = self._build_legacy_cancel_tx()
        return V0Transaction(address_table_lookups=[self._alt_info]).add(legacy_tx)

    def _build_prep_tx_list_before_emulate(self) -> List[SolTxListInfo]:
        assert self.is_valid()
        tx_list_info_list = super()._build_prep_tx_list_before_emulate()

        self._alt_tx_set = self._alt_builder.build_alt_tx_set(self._alt_info)
        alt_tx_list_info_list = self._alt_builder.build_prep_alt_list(self._alt_tx_set)

        if len(tx_list_info_list) > 0:
            tx_list_info_list[-1].extend(alt_tx_list_info_list[0])
            alt_tx_list_info_list = alt_tx_list_info_list[1:]
        if len(alt_tx_list_info_list) > 0:
            tx_list_info_list.extend(alt_tx_list_info_list)

        return tx_list_info_list

    def prep_before_emulate(self) -> bool:
        result = super().prep_before_emulate()
        self._alt_builder.update_alt_info_list([self._alt_info])
        return result

    def _post_execute(self) -> None:
        if (self._alt_tx_set is None) or (len(self._alt_tx_set) == 0):
            return

        try:
            tx_list_info_list = self._alt_builder.build_done_alt_tx_set(self._alt_tx_set)
            self._execute_prep_tx_list(tx_list_info_list)
        except (Exception,):
            # TODO: Move this skip into solana receipt checker
            pass

    def execute(self) -> NeonTxResultInfo:
        try:
            return super().execute()
        finally:
            self._post_execute()


class BaseNoChainIdNeonStrategy:
    @staticmethod
    def _validate_tx_wo_chainid(self) -> bool:
        return not self._neon_tx.hasChainId()

    @staticmethod
    def _build_tx_wo_chainid(self, idx: int) -> Transaction:
        return TransactionWithComputeBudget(compute_units=self._compute_unit_cnt).add(
            self._builder.make_partial_call_or_continue_from_account_data_no_chainid_instruction(
                self._iter_evm_step_cnt, idx
            )
        )


@logged_group("neon.MemPool")
class NoChainIdNeonTxStrategy(HolderNeonTxStrategy, BaseNoChainIdNeonStrategy):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self) -> bool:
        self._validation_error_msg = None
        if not self._validate_tx_wo_chainid(self):
            self._validation_error_msg = 'Normal transaction'
            return False

        return self._validate_tx_size()

    def build_tx(self, idx=0) -> Transaction:
        return self._build_tx_wo_chainid(self, idx)


@logged_group("neon.MemPool")
class AltNoChainIdNeonTxStrategy(AltHolderNeonTxStrategy, BaseNoChainIdNeonStrategy):
    NAME = 'AltExecuteTrxFromAccountDataIterativeOrContinueNoChainId'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def validate(self) -> bool:
        self._validation_error_msg = None
        if not self._validate_tx_wo_chainid(self):
            self._validation_error_msg = 'Normal transaction'
            return False

        return self._validate_tx_size()

    def _build_legacy_tx(self, idx=0) -> Transaction:
        return self._build_tx_wo_chainid(self, idx)


@logged_group("neon.MemPool")
class NeonTxSendStrategyExecutor:
    STRATEGY_LIST = [
        SimpleNeonTxStrategy,
        IterativeNeonTxStrategy, HolderNeonTxStrategy, AltHolderNeonTxStrategy,
        NoChainIdNeonTxStrategy, AltNoChainIdNeonTxStrategy
    ]

    def __init__(self, solana: SolanaInteractor, resource: OperatorResourceInfo, neon_tx: NeonTx):
        super().__init__()
        self._ctx = NeonTxSendCtx(solana, resource, neon_tx)
        self._operator = f'{str(self._ctx.resource)}'

    def execute(self, neon_tx_exec_cfg: NeonTxExecCfg) -> NeonTxResultInfo:
        self._init_emulated_cfg(neon_tx_exec_cfg)
        return self._execute()

    def _init_emulated_cfg(self, neon_tx_exec_cfg: NeonTxExecCfg) -> None:
        self._ctx.set_emulated_evm_step_cnt(neon_tx_exec_cfg.evm_step_cnt)
        self._ctx.account_tx_list_builder.build_tx(neon_tx_exec_cfg.account_dict)

    def _emulate_neon_tx(self) -> None:
        emulated_result: NeonEmulatedResult = call_trx_emulated(self._ctx.neon_tx)
        neon_tx_exec_cfg = NeonTxExecCfg.from_emulated_result(emulated_result)
        self._init_emulated_cfg(neon_tx_exec_cfg)

    def _execute(self) -> NeonTxResultInfo:
        for Strategy in self.STRATEGY_LIST:
            try:
                strategy: BaseNeonTxStrategy = Strategy(self._ctx)
                if not strategy.validate():
                    self.debug(f'Skip strategy {Strategy.NAME}: {strategy.validation_error_msg}')
                    continue
                self.debug(f'Use strategy {Strategy.NAME}')

                strategy.prep_before_emulate()
                for i in range(RETRY_ON_FAIL):
                    self._emulate_neon_tx()
                    if not strategy.validate():
                        self.debug(f'Skip strategy {Strategy.NAME}: {strategy.validation_error_msg}')
                        continue

                    if strategy.prep_after_emulate():
                        continue
                    return strategy.execute()
                raise RuntimeError('fail to sync the emulation and the execution')

            except (BlockedAccountsError, NodeBehindError, SolanaUnavailableError):
                raise
            except Exception as e:
                if (not Strategy.IS_SIMPLE) or (not SolReceiptParser(e).check_if_budget_exceeded()):
                    raise
        raise RuntimeError('transaction is too big for execution')
