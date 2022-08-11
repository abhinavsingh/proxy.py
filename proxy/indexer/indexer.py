from __future__ import annotations

import time

from typing import Iterator, List, Optional, Dict, Tuple, Any, Deque, cast
from collections import deque
from logged_groups import logged_group, logging_context
from solana.system_program import SYS_PROGRAM_ID
from solana.publickey import PublicKey

from ..indexer.i_indexer_stat_exporter import IIndexerStatExporter
from ..indexer.indexer_base import IndexerBase
from ..indexer.indexer_db import IndexerDB
from ..indexer.solana_tx_meta_collector import SolTxMetaCollector, SolTxMetaDict, SolHistoryNotFound
from ..indexer.solana_tx_meta_collector import FinalizedSolTxMetaCollector, ConfirmedSolTxMetaCollector
from ..indexer.utils import MetricsToLogger
from ..indexer.indexed_objects import NeonIndexedTxInfo, NeonIndexedHolderInfo, NeonAccountInfo
from ..indexer.indexed_objects import NeonIndexedBlockInfo, NeonIndexedBlockDict

from ..common_neon.data import NeonTxStatData
from ..common_neon.utils import NeonTxInfo, SolanaBlockInfo
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_receipt_parser import SolReceiptParser
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxCostInfo, SolTxReceiptInfo, SolNeonIxReceiptInfo
from ..common_neon.evm_log_decoder import decode_neon_tx_result
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import CANCEL_TIMEOUT


class SolNeonTxDecoderState:
    # Iterate:
    #   for solana_block in block_range(start_block_slot, stop_block_slot):
    #       for solana_tx in solana_block.solana_tx_list:
    #           for solana_ix in solana_tx.solana_ix_list:
    #               solana_ix.level <- level in stack of calls
    #  ....
    def __init__(self, sol_tx_meta_collector: SolTxMetaCollector,
                 start_block_slot: int,
                 neon_block: Optional[NeonIndexedBlockInfo]):
        self._start_time = time.time()
        self._init_block_slot = start_block_slot
        self._start_block_slot = start_block_slot
        self._stop_block_slot = start_block_slot
        self._sol_tx_meta_cnt = 0
        self._sol_neon_ix_cnt = 0
        self._sol_tx_meta_collector = sol_tx_meta_collector

        self._sol_tx: Optional[SolTxReceiptInfo] = None
        self._sol_tx_meta: Optional[SolTxMetaInfo] = None
        self._sol_neon_ix: Optional[SolNeonIxReceiptInfo] = None
        self._neon_tx_key_list: List[Optional[NeonIndexedTxInfo.Key]] = []

        self._neon_block_deque: Deque[Tuple[NeonIndexedBlockInfo, bool]] = deque([])
        if neon_block is not None:
            self.set_neon_block(neon_block)

    def shift_to_collector(self, collector: SolTxMetaCollector):
        self._start_block_slot = self._stop_block_slot + 1
        self._stop_block_slot = self._start_block_slot
        self._sol_tx_meta_collector = collector

    def set_stop_block_slot(self, block_slot: int) -> None:
        self._stop_block_slot = block_slot

    def set_neon_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        if (len(self._neon_block_deque) > 0) and self._neon_block_deque[0][1]:
            self._neon_block_deque.popleft()
        is_finalized = self._sol_tx_meta_collector.is_finalized
        self._neon_block_deque.append((neon_block, is_finalized))

    @property
    def process_time_ms(self) -> float:
        return (time.time() - self._start_time) * 1000

    @property
    def start_block_slot(self) -> int:
        return self._start_block_slot

    @property
    def stop_block_slot(self) -> int:
        return self._stop_block_slot

    @property
    def commitment(self) -> str:
        return self._sol_tx_meta_collector.commitment

    @property
    def neon_block_cnt(self) -> int:
        return len(self._neon_block_deque)

    @property
    def sol_tx_meta_cnt(self) -> int:
        return self._sol_tx_meta_cnt

    @property
    def sol_neon_ix_cnt(self) -> int:
        return self._sol_neon_ix_cnt

    def has_neon_block(self) -> bool:
        return self.neon_block_cnt > 0

    @property
    def neon_block(self) -> NeonIndexedBlockInfo:
        assert self.has_neon_block()
        return self._neon_block_deque[-1][0]

    @property
    def is_neon_block_finalized(self) -> bool:
        assert self.has_neon_block()
        return self._neon_block_deque[-1][1]

    @property
    def block_slot(self) -> int:
        return self.neon_block.block_slot

    def iter_sol_tx_meta(self) -> Iterator[SolTxMetaInfo]:
        try:
            # Solana returns transactions from the last processed one and then goes back into history
            collector = self._sol_tx_meta_collector
            for self._sol_tx_meta in collector.iter_tx_meta(self._stop_block_slot, self._start_block_slot):
                self._sol_tx_meta_cnt += 1
                yield self._sol_tx_meta
        finally:
            self._sol_tx_meta = None

    def set_neon_tx(self, tx: NeonIndexedTxInfo) -> None:
        assert len(self._neon_tx_key_list)
        self._neon_tx_key_list[-1] = tx.key

    def has_neon_tx(self) -> bool:
        return (len(self._neon_tx_key_list) > 1) and (self._neon_tx_key_list[-2] is not None)

    @property
    def neon_tx(self) -> NeonIndexedTxInfo:
        assert self.has_sol_tx()
        tx_key = cast(NeonIndexedTxInfo.Key, self._neon_tx_key_list[-2])
        return self.neon_block.get_neon_tx(tx_key, self._sol_neon_ix)

    def has_sol_tx(self) -> bool:
        return self._sol_tx is not None

    @property
    def sol_tx(self) -> SolTxReceiptInfo:
        assert self.has_sol_tx()
        return cast(SolTxReceiptInfo, self._sol_tx)

    def has_sol_neon_ix(self) -> bool:
        return self._sol_neon_ix is not None

    @property
    def sol_neon_ix(self) -> SolNeonIxReceiptInfo:
        return cast(SolNeonIxReceiptInfo, self._sol_neon_ix)

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        assert self._sol_tx_meta is not None

        try:
            self._sol_tx = SolTxReceiptInfo(self._sol_tx_meta)
            for self._sol_neon_ix in self._sol_tx.iter_sol_neon_ix():
                if len(self._neon_tx_key_list) < self._sol_neon_ix.level:
                    # goes to the upper level
                    self._neon_tx_key_list.append(None)
                elif len(self._neon_tx_key_list) > self._sol_neon_ix.level:
                    # returns to the back level
                    self._neon_tx_key_list.pop()
                else:
                    # moves to the next instruction on the same level
                    self._neon_tx_key_list[-1] = None

                self._sol_neon_ix_cnt += 1
                yield self._sol_neon_ix
        finally:
            self._sol_tx = None
            self._sol_neon_ix = None
            self._neon_tx_key_list.clear()

    def iter_neon_block(self) -> Iterator[NeonIndexedBlockInfo]:
        for neon_block, _ in self._neon_block_deque:
            yield neon_block


@logged_group("neon.Indexer")
class DummyIxDecoder:
    _name = 'Unknown'

    def __init__(self, state: SolNeonTxDecoderState):
        self._state = state
        self.debug(f'{self} ...')

    def __str__(self):
        return f'{self._name} {self._state.sol_neon_ix}'

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        ix = self._state.sol_neon_ix
        return self._decoding_skip(f'no logic to decode the instruction {self}({ix.ix_data.hex()[:8]})')

    @property
    def state(self) -> SolNeonTxDecoderState:
        return self._state

    def _init_neon_tx_from_holder(self, holder_account: str,
                                  storage_account: str,
                                  iter_blocked_account: Iterator[str]) -> Optional[NeonIndexedTxInfo]:
        block = self._state.neon_block
        ix = self._state.sol_neon_ix

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = block.get_neon_tx(key, ix)
        if tx is not None:
            return tx

        holder = block.get_neon_holder(holder_account, ix)
        if holder is None:
            self._decoding_skip(f'no holder account {holder_account}')
            return None

        rlp_sig = holder.data[0:65]
        rlp_len = int.from_bytes(holder.data[65:73], 'little')
        rlp_endpos = 73 + rlp_len
        rlp_data = holder.data[73:rlp_endpos]

        neon_tx = NeonTxInfo(rlp_sig=rlp_sig, rlp_data=bytes(rlp_data))
        if neon_tx.error:
            self.warning(f'Neon tx rlp error: {neon_tx.error}')
            return None

        tx = block.add_neon_tx(key, neon_tx, ix)
        tx.set_holder_account(holder)
        self._decoding_done(holder, f'init {tx.neon_tx} from holder')
        return tx

    def _decoding_success(self, indexed_obj: Any, msg: str) -> bool:
        """
        The instruction has been successfully parsed:
        - Mark the instruction as used;
        - log the success message.
        """
        self.debug(f'decoding success: {msg} - {indexed_obj}')
        return True

    def _decoding_done(self, indexed_obj: Any, msg: str) -> bool:
        """
        Assembling of the object has been successfully finished.
        """
        self.debug(f'decoding done: {msg} - {indexed_obj}')
        ix = self._state.sol_neon_ix
        block = self._state.neon_block
        if isinstance(indexed_obj, NeonIndexedTxInfo):
            block.done_neon_tx(indexed_obj, ix)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            block.done_neon_holder(indexed_obj, ix)
        return True

    def _decoding_skip(self, reason: str) -> bool:
        """Skip decoding of the instruction"""
        self.debug(f'decoding skip: {reason}')
        return False

    def _decoding_fail(self, indexed_obj: Any, reason: str) -> bool:
        """
        Assembling of objects has been failed:
        - destroy the intermediate objects;
        - unmark all instructions as used.

        Show errors in warning mode because it can be a result of restarting.
        """
        self.warning(f'decoding fail: {reason} - {indexed_obj}')

        ix = self._state.sol_neon_ix
        block = self._state.neon_block
        if isinstance(indexed_obj, NeonIndexedTxInfo):
            block.fail_neon_tx(indexed_obj, ix)
        elif isinstance(indexed_obj, NeonIndexedHolderInfo):
            block.fail_neon_holder(indexed_obj, ix)
        return False

    def _decode_tx(self, tx: NeonIndexedTxInfo, msg: str) -> bool:
        self._state.set_neon_tx(tx)

        if not tx.neon_tx_res.is_valid():
            if decode_neon_tx_result(self._state.sol_neon_ix.iter_log(), tx.neon_tx.sig, tx.neon_tx_res):
                ix = self._state.sol_neon_ix
                tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)

        if tx.neon_tx_res.is_valid() and (tx.status != NeonIndexedTxInfo.Status.DONE):
            return self._decoding_done(tx, msg)
        return self._decoding_success(tx, msg)


class WriteIxDecoder(DummyIxDecoder):
    _name = 'Write'

    def _decode_data_chunk(self) -> NeonIndexedHolderInfo.DataChunk:
        ix_data = self.state.sol_neon_ix.ix_data
        # No enough bytes to get length of chunk
        if len(ix_data) < 17:
            return NeonIndexedHolderInfo.DataChunk.init_empty()

        return NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix_data[4:8], 'little'),
            length=int.from_bytes(ix_data[8:16], 'little'),
            data=ix_data[16:],
        )

    def execute(self) -> bool:
        chunk = self._decode_data_chunk()
        if not chunk.is_valid():
            return self._decoding_skip(f'bad data chunk {chunk}')

        ix = self.state.sol_neon_ix
        if ix.account_cnt < 1:
            return self._decoding_skip(f'no enough accounts {ix.account_cnt}')

        account = ix.get_account(0)
        block = self.state.neon_block
        holder = block.get_neon_holder(account, ix) or block.add_neon_holder(account, ix)

        # Write the received chunk into the holder account buffer
        holder.add_data_chunk(chunk)
        return self._decoding_success(holder, f'add chunk {chunk}')


class WriteWithHolderIxDecoder(WriteIxDecoder):
    _name = 'WriteWithHolder'

    def _decode_data_chunk(self) -> NeonIndexedHolderInfo.DataChunk:
        # No enough bytes to get length of chunk
        ix = self.state.sol_neon_ix
        ix_data = ix.ix_data
        if len(ix_data) < 22:
            return NeonIndexedHolderInfo.DataChunk.init_empty()

        return NeonIndexedHolderInfo.DataChunk(
            offset=int.from_bytes(ix_data[9:13], 'little'),
            length=int.from_bytes(ix_data[13:21], 'little'),
            data=ix.ix_data[21:]
        )


class CreateAccountIxDecoder(DummyIxDecoder):
    _name = 'CreateAccount'

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 41:
            return self._decoding_skip(f'not enough data to get the Neon account {len(ix.ix_data)}')

        neon_account = "0x" + ix.ix_data[8+8+4:][:20].hex()
        pda_account = ix.get_account(1)
        code_account = ix.get_account(3)
        if code_account == str(SYS_PROGRAM_ID) or code_account == '':
            code_account = None

        account_info = NeonAccountInfo(
            neon_account, pda_account, code_account,
            ix.block_slot, None, ix.sol_sig
        )

        self.state.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create account')


class CreateAccount2IxDecoder(DummyIxDecoder):
    _name = 'CreateAccount2'

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 21:
            return self._decoding_skip(f'not enough data to get the Neon account {len(ix.ix_data)}')

        neon_account = "0x" + ix.ix_data[1:][:20].hex()
        pda_account = ix.get_account(2)
        code_account = ix.get_account(3)
        if code_account == '':
            code_account = None

        account_info = NeonAccountInfo(
            neon_account, pda_account, code_account,
            ix.block_slot, None, ix.sol_sig
        )
        self.state.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'create account')


class ResizeStorageAccountIxDecoder(DummyIxDecoder):
    _name = 'ResizeStorageAccount'

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        pda_account = ix.get_account(0)
        code_account = ix.get_account(2)

        account_info = NeonAccountInfo(
            None, pda_account, code_account,
            ix.block_slot, None, ix.sol_sig
        )
        self.state.neon_block.add_neon_account(account_info, ix)
        return self._decoding_success(account_info, 'resize of account')


class CallFromRawIxDecoder(DummyIxDecoder):
    _name = 'CallFromRaw'

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if len(ix.ix_data) < 92:
            return self._decoding_skip('no enough data to get the Neon tx')

        rlp_sig = ix.ix_data[25:90]
        rlp_data = ix.ix_data[90:]

        neon_tx = NeonTxInfo(rlp_sig=rlp_sig, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        key = NeonIndexedTxInfo.Key.from_ix(ix)
        tx = self.state.neon_block.add_neon_tx(key, neon_tx, ix)
        return self._decode_tx(tx, 'call raw tx')


class OnResultIxDecoder(DummyIxDecoder):
    _name = 'OnResult'

    def execute(self) -> bool:
        if not self.state.has_neon_tx():
            return self._decoding_skip('no Neon tx to add result')

        ix = self.state.sol_neon_ix
        tx = self.state.neon_tx
        log = ix.ix_data

        status = '0x1' if log[1] < 0xd0 else '0x0'
        gas_used = hex(int.from_bytes(log[2:10], 'little'))
        return_value = log[10:].hex()

        tx.neon_tx_res.fill_result(status=status, gas_used=gas_used, return_value=return_value)
        tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
        return self._decode_tx(tx, 'tx result')


class OnEventIxDecoder(DummyIxDecoder):
    _name = 'OnEvent'

    def execute(self) -> bool:
        if not self.state.has_neon_tx():
            return self._decoding_skip('no Neon tx to add events')

        ix = self.state.sol_neon_ix
        tx = self.state.neon_tx
        log = ix.ix_data

        address = log[1:21]
        topic_cnt = int().from_bytes(log[21:29], 'little')
        topic_list = []
        pos = 29
        for _ in range(topic_cnt):
            topic_bin = log[pos:pos + 32]
            topic_list.append('0x' + topic_bin.hex())
            pos += 32
        data = log[pos:]

        tx_log_idx = len(tx.neon_tx_res.log_list)
        rec = {
            'address': '0x' + address.hex(),
            'topics': topic_list,
            'data': '0x' + data.hex(),
            'transactionHash': tx.neon_tx.sig,
            'transactionLogIndex': hex(tx_log_idx),
            # 'logIndex': hex(tx_log_idx), # set when transaction found
            # 'transactionIndex': hex(ix.idx), # set when transaction found
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }

        tx.neon_tx_res.append_record(rec)
        return self._decode_tx(tx, 'tx event')


class PartialCallIxDecoder(DummyIxDecoder):
    _name = 'PartialCallFromRawEthereumTX'

    def execute(self) -> bool:
        first_blocked_account_idx = 7

        ix = self.state.sol_neon_ix
        if ix.account_cnt < first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')
        if len(ix.ix_data) < 100:
            return self._decoding_skip('no enough data to get arguments')

        rlp_sig = ix.ix_data[33:98]
        rlp_data = ix.ix_data[98:]

        neon_tx = NeonTxInfo(rlp_sig=rlp_sig, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        block = self.state.neon_block

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(first_blocked_account_idx)

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = block.get_neon_tx(key, ix)
        if (tx is not None) and (tx.neon_tx.sig != neon_tx.sig):
            self._decoding_fail(tx, f'Neon tx sign {neon_tx.sig} != {tx.neon_tx.sig}')
            tx = None

        if tx is None:
            tx = block.add_neon_tx(key, neon_tx, ix)

        step_count = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(step_count)
        return self._decode_tx(tx, 'partial tx call')


class PartialCallV02IxDecoder(PartialCallIxDecoder):
    _name = 'PartialCallFromRawEthereumTXv02'


class PartialCallOrContinueIxDecoder(PartialCallIxDecoder):
    _name = 'PartialCallOrContinueFromRawEthereumTX'


class ContinueIxDecoder(DummyIxDecoder):
    _name = 'Continue'
    _first_blocked_account_idx = 5

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')
        if len(ix.ix_data) < 14:
            return self._decoding_skip('no enough data to get arguments')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(self._first_blocked_account_idx)

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = self.state.neon_block.get_neon_tx(key, ix)
        if not tx:
            return self._decode_skip(f'no transaction at the storage {storage_account}')

        step_cnt = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(step_cnt)
        return self.decode_tx(tx, 'continue tx call')


class ContinueV02IxDecoder(ContinueIxDecoder):
    _name = 'ContinueV02'
    _first_blocked_account_idx = 6


class ExecuteTrxFromAccountIxDecoder(DummyIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterative'
    _first_blocked_account_idx = 5

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        if ix.account_cnt < self._first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        holder_account = ix.get_account(0)
        storage_account = ix.get_account(1)
        iter_blocked_account = ix.iter_account(self._first_blocked_account_idx)

        tx = self._init_neon_tx_from_holder(holder_account, storage_account, iter_blocked_account)
        if not tx:
            return self._decoding_skip(f'fail to init storage {storage_account} from holder {holder_account}')

        step_cnt = int.from_bytes(ix.ix_data[5:13], 'little')
        ix.set_neon_step_cnt(step_cnt)
        return self._decode_tx(tx, 'execute/continue tx from holder')


class ExecuteTrxFromAccountV02IxDecoder(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeV02'
    _first_blocked_account_idx = 7


class ExecuteOrContinueIxParser(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeOrContinue'
    _first_blocked_account_idx = 7


class ExecuteOrContinueNoChainIdIxParser(ExecuteTrxFromAccountIxDecoder):
    _name = 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId'
    _first_blocked_account_idx = 7


class CancelIxDecoder(DummyIxDecoder):
    _name = 'Cancel'

    def execute(self) -> bool:
        ix = self.state.sol_neon_ix
        first_blocked_account_idx = 3
        if ix.account_cnt < first_blocked_account_idx + 1:
            return self._decoding_skip('no enough accounts')

        storage_account = ix.get_account(0)
        iter_blocked_account = ix.iter_account(first_blocked_account_idx)

        key = NeonIndexedTxInfo.Key(storage_account, iter_blocked_account)
        tx = self.state.neon_block.get_neon_tx(key, ix)
        if not tx:
            return self._decoding_skip(f'cannot find tx in the storage {storage_account}')

        # TODO: get used gas
        tx.neon_tx_res.fill_result(status='0x0', gas_used='0x0', return_value='')
        tx.neon_tx_res.fill_sol_sig_info(ix.sol_sig, ix.idx, ix.inner_idx)
        return self._decode_tx(tx, 'cancel tx')


class CancelV02IxDecoder(CancelIxDecoder):
    _name = 'CancelV02'


class ERC20CreateTokenAccountIxDecoder(DummyIxDecoder):
    _name = 'ERC20CreateTokenAccount'


class FinalizeIxDecode(DummyIxDecoder):
    _name = 'Finalize'


class CallIxDecoder(DummyIxDecoder):
    _name = 'Call'


class CreateAccountWithSeedIxDecoder(DummyIxDecoder):
    _name = 'CreateAccountWithSeed'


class DepositIxDecoder(DummyIxDecoder):
    _name = 'Deposit'


class MigrateAccountIxDecoder(DummyIxDecoder):
    _name = 'MigrateAccount'


class UpdateValidsTableIxDecoder(DummyIxDecoder):
    _name = 'UpdateValidsTable'


@logged_group("neon.Indexer")
class Indexer(IndexerBase):
    def __init__(self, solana_url, indexer_stat_exporter: IIndexerStatExporter):
        solana = SolanaInteractor(solana_url)
        self._db = IndexerDB()
        last_known_slot = self._db.get_min_receipt_block_slot()
        super().__init__(solana, last_known_slot)
        self._cancel_tx_executor = CancelTxExecutor(solana, get_solana_accounts()[0])
        self._counted_logger = MetricsToLogger()
        self._stat_exporter = indexer_stat_exporter
        self._last_stat_time = 0.0
        sol_tx_meta_dict = SolTxMetaDict()
        self._finalized_sol_tx_collector = FinalizedSolTxMetaCollector(sol_tx_meta_dict, self._solana, self._last_slot)
        self._confirmed_sol_tx_collector = ConfirmedSolTxMetaCollector(sol_tx_meta_dict, self._solana)
        self._confirmed_block_slot: Optional[int] = None
        self._neon_block_dict = NeonIndexedBlockDict()

        self._sol_neon_ix_decoder_dict: Dict[int, Any] = {
            0x00: WriteIxDecoder,
            0x01: FinalizeIxDecode,
            0x02: CreateAccountIxDecoder,
            0x03: CallIxDecoder,
            0x04: CreateAccountWithSeedIxDecoder,
            0x05: CallFromRawIxDecoder,
            0x06: OnResultIxDecoder,
            0x07: OnEventIxDecoder,
            0x09: PartialCallIxDecoder,
            0x0a: ContinueIxDecoder,
            0x0b: ExecuteTrxFromAccountIxDecoder,
            0x0c: CancelIxDecoder,
            0x0d: PartialCallOrContinueIxDecoder,
            0x0e: ExecuteOrContinueIxParser,
            0x0f: ERC20CreateTokenAccountIxDecoder,
            0x11: ResizeStorageAccountIxDecoder,
            0x12: WriteWithHolderIxDecoder,
            0x13: PartialCallV02IxDecoder,
            0x14: ContinueV02IxDecoder,
            0x15: CancelV02IxDecoder,
            0x16: ExecuteTrxFromAccountV02IxDecoder,
            0x17: UpdateValidsTableIxDecoder,
            0x18: CreateAccount2IxDecoder,
            0x19: DepositIxDecoder,
            0x1a: MigrateAccountIxDecoder,
            0x1b: ExecuteOrContinueNoChainIdIxParser
        }

    def _cancel_old_neon_txs(self, neon_block: NeonIndexedBlockInfo) -> None:
        for tx in neon_block.iter_neon_tx():
            if (tx.storage_account != '') and (abs(tx.block_slot - neon_block.block_slot) > CANCEL_TIMEOUT):
                self._cancel_neon_tx(tx)

        self._cancel_tx_executor.execute_tx_list()
        self._cancel_tx_executor.clear()

    def _cancel_neon_tx(self, tx: NeonIndexedTxInfo) -> bool:
        # We've already indexed the transaction
        if tx.neon_tx_res.is_valid():
            return True

        # We've already sent Cancel and are waiting for receipt
        if tx.status != NeonIndexedTxInfo.Status.IN_PROGRESS:
            return True

        if not tx.blocked_account_cnt:
            self.warning(f"neon tx {tx.neon_tx} hasn't blocked accounts.")
            return False

        storage = self._solana.get_storage_account_info(PublicKey(tx.storage_account))
        if not storage:
            self.warning(f'storage {tx.storage_account} for neon tx {tx.neon_tx.sig} is empty')
            return False

        if storage.caller != tx.neon_tx.addr[2:]:
            self.warning(
                f'storage {tx.storage_account} for neon tx {tx.neon_tx.sig} has another caller: ' +
                f'{storage.caller} != {tx.neon_tx.addr[2:]}'
            )
            return False

        tx_nonce = int(tx.neon_tx.nonce[2:], 16)
        if storage.nonce != tx_nonce:
            self.warning(
                f'storage {tx.storage_account} for neon tx {tx.neon_tx.sig} has another nonce: ' +
                f'{storage.nonce} != {tx_nonce}'
            )
            return False

        if len(storage.account_list) == 0:
            self.warning(f'storage {tx.storage_account} for neon tx {tx.neon_tx.sig} has empty account list.')
            return False

        if len(storage.account_list) != tx.blocked_account_cnt:
            self.warning(f'neon tx {tx.neon_tx} has another list of accounts than storage.')
            return False

        for (writable, account), (idx, tx_account) in zip(storage.account_list, enumerate(tx.iter_blocked_account())):
            if account != tx_account:
                self.warning(
                    f'neon tx {tx.neon_tx} has another list of accounts than storage: ' +
                    f'{idx}: {account} != {tx_account}'
                )
                return False

        if not self._cancel_tx_executor.add_blocked_storage_account(storage):
            self.warning(
                f'neon tx {tx.neon_tx} uses the storage account {tx.storage_account}' +
                'which is already in the list on unlock'
            )
            return False

        self.debug(f'Neon tx is blocked: storage {tx.storage_account}, {tx.neon_tx}, {storage.account_list}')
        tx.set_status(NeonIndexedTxInfo.Status.CANCELED)
        return True

    def _save_checkpoint(self) -> None:
        cache_stat = self._neon_block_dict.stat
        self._db.set_min_receipt_block_slot(cache_stat.min_block_slot)

    def _complete_neon_block(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> None:
        if not state.has_neon_block():
            return

        neon_block = state.neon_block
        is_finalized = state.is_neon_block_finalized
        backup_is_finalized = neon_block.is_finalized
        if backup_is_finalized:
            return

        try:
            neon_block.set_finalized(is_finalized)
            if not neon_block.is_completed:
                self._db.submit_block(neon_block)
                neon_block.complete_block(sol_tx_meta)
            elif is_finalized:
                # the confirmed block becomes finalized
                self._db.finalize_block(neon_block)

            # Add block to cache only after indexing and applying last changes to DB
            self._neon_block_dict.add_neon_block(neon_block, sol_tx_meta)
            if is_finalized:
                self._neon_block_dict.finalize_neon_block(neon_block, sol_tx_meta)
                self._submit_block_status(neon_block)
                self._save_checkpoint()

            self._submit_status()
        except (Exception,):
            # Revert finalized status
            neon_block.set_finalized(backup_is_finalized)
            raise

    def _submit_block_status(self, neon_block: NeonIndexedBlockInfo) -> None:
        for tx in neon_block.iter_done_neon_tx():
            # TODO: check operator of tx
            self._submit_neon_tx_status(tx)

    def _submit_status(self) -> None:
        now = time.time()
        if abs(now - self._last_stat_time) < 1:
            return
        self._last_stat_time = now
        self._stat_exporter.on_db_status(self._db.status())
        self._stat_exporter.on_solana_rpc_status(self._solana.is_healthy())

    def _submit_neon_tx_status(self, tx: NeonIndexedTxInfo) -> None:
        neon_tx_hash = tx.neon_tx.sig
        neon_income = int(tx.neon_tx_res.gas_used, 0) * int(tx.neon_tx.gas_price, 0)  # TODO: get gas usage from ixs
        if tx.holder_account != '':
            tx_type = 'holder'
        elif tx.storage_account != '':
            tx_type = 'iterative'
        else:
            tx_type = 'single'
        is_canceled = tx.neon_tx_res.status == '0x0'
        sol_spent = tx.sol_spent
        neon_tx_stat_data = NeonTxStatData(neon_tx_hash, sol_spent, neon_income, tx_type, is_canceled)
        neon_tx_stat_data.sol_tx_cnt = tx.sol_tx_cnt
        for ix in tx.iter_sol_neon_ix():
            neon_tx_stat_data.neon_step_cnt += ix.neon_step_cnt
            neon_tx_stat_data.bpf_cycle_cnt += ix.used_bpf_cycle_cnt

        self._stat_exporter.on_neon_tx_result(neon_tx_stat_data)

    def _get_sol_block_deque(self, state: SolNeonTxDecoderState, sol_tx_meta: SolTxMetaInfo) -> Deque[SolanaBlockInfo]:
        if not state.has_neon_block():
            sol_block = self._solana.get_block_info(sol_tx_meta.block_slot)
            if sol_block.is_empty():
                raise SolHistoryNotFound(f"can't get block: {sol_tx_meta.block_slot}")
            return deque([sol_block])

        start_block_slot = state.block_slot
        block_slot_list = [block_slot for block_slot in range(start_block_slot + 1, sol_tx_meta.block_slot + 1)]
        sol_block_list = self._solana.get_block_info_list(block_slot_list, state.commitment)
        result_sol_block_deque: Deque[SolanaBlockInfo] = deque()
        for sol_block in sol_block_list:
            if sol_block.is_empty():
                pass
            elif sol_block.parent_block_slot == start_block_slot:
                result_sol_block_deque.append(sol_block)
                start_block_slot = sol_block.block_slot

        if (len(result_sol_block_deque) == 0) or (result_sol_block_deque[-1].block_slot != sol_tx_meta.block_slot):
            raise SolHistoryNotFound(f"can't get block history: {start_block_slot + 1} -> {sol_tx_meta.block_slot}")
        return result_sol_block_deque

    def _locate_neon_block(self, sol_tx_meta: SolTxMetaInfo, state: SolNeonTxDecoderState) -> NeonIndexedBlockInfo:
        # The same block
        if state.has_neon_block():
            if state.neon_block.block_slot == sol_tx_meta.block_slot:
                return state.neon_block
            # The next step, the indexer will choose another block, that is why here is saving of block in DB, cache ...
            self._complete_neon_block(state, sol_tx_meta)

        neon_block = self._neon_block_dict.get_neon_block(sol_tx_meta.block_slot)
        if neon_block:
            pass  # The parsed block from cache
        else:
            # A new block with history from the Solana network
            sol_block_deque = self._get_sol_block_deque(state, sol_tx_meta)
            if state.has_neon_block():
                neon_block = state.neon_block.clone(sol_block_deque)
            else:
                neon_block = NeonIndexedBlockInfo(sol_block_deque)
        state.set_neon_block(neon_block)
        return neon_block

    def _run_sol_tx_collector(self, state: SolNeonTxDecoderState) -> None:
        stop_block_slot = self._solana.get_block_slot(state.commitment)
        state.set_stop_block_slot(stop_block_slot)
        if stop_block_slot < state.start_block_slot:
            return

        for sol_tx_meta in state.iter_sol_tx_meta():
            neon_block = self._locate_neon_block(sol_tx_meta, state)
            if neon_block.is_completed:
                # self.debug(f'ignore parsed tx {sol_tx_meta}')
                continue

            neon_block.add_sol_tx_cost(SolTxCostInfo(sol_tx_meta))

            if SolReceiptParser(sol_tx_meta.tx).check_if_error():
                # self.debug(f'ignore failed tx {sol_tx_meta}')
                continue

            for sol_neon_ix in state.iter_sol_neon_ix():
                SolNeonIxDecoder = (self._sol_neon_ix_decoder_dict.get(sol_neon_ix.program_ix) or DummyIxDecoder)
                with logging_context(sol_neon_ix=sol_neon_ix.req_id):
                    SolNeonIxDecoder(state).execute()

        with logging_context(ident='end-of-range'):
            stop_block_slot = state.stop_block_slot
            sol_tx_meta = SolTxMetaInfo(stop_block_slot, f'END-OF-BLOCK-RANGE-{state.commitment}', {})
            if (not state.has_neon_block()) or (state.block_slot != stop_block_slot):
                self._locate_neon_block(sol_tx_meta, state)

            self._complete_neon_block(state, sol_tx_meta)

    def _has_new_blocks(self) -> bool:
        if self._confirmed_block_slot is None:
            return True
        confirmed_block_slot = self._solana.get_block_slot(self._confirmed_sol_tx_collector.commitment)
        return self._confirmed_block_slot != confirmed_block_slot

    def process_functions(self):
        if not self._has_new_blocks():
            return

        start_block_slot = self._finalized_sol_tx_collector.last_block_slot + 1
        finalized_neon_block = self._neon_block_dict.finalized_neon_block
        if finalized_neon_block is not None:
            start_block_slot = finalized_neon_block.block_slot + 1

        try:
            state = SolNeonTxDecoderState(self._finalized_sol_tx_collector, start_block_slot, finalized_neon_block)
            self._run_sol_tx_collector(state)
        except SolHistoryNotFound as err:
            self.debug(f'skip parsing of confirmed history: {str(err)}')
            return

        # If there were a lot of transactions in the finalized state,
        # the head of finalized blocks will go forward
        # and there are no reason to parse confirmed blocks,
        # because on next iteration there will be the next portion of finalized blocks
        finalized_block_slot = self._solana.get_block_slot(state.commitment)
        if (finalized_block_slot - state.stop_block_slot) < 3:
            state.shift_to_collector(self._confirmed_sol_tx_collector)
            try:
                self._run_sol_tx_collector(state)
            except SolHistoryNotFound as err:
                self.debug(f'skip parsing of confirmed history: {str(err)}')
            else:
                # Activate branch of history
                self._db.activate_block_list(state.iter_neon_block())
                # Here must be confirmed blocks
                assert state.has_neon_block()
                self._cancel_old_neon_txs(state.neon_block)
                # Save confirmed block only after successfully parsing
                self._confirmed_block_slot = state.stop_block_slot

        self._print_stat(state)
        self._submit_status()

    def _print_stat(self, state: SolNeonTxDecoderState) -> None:
        cache_stat = self._neon_block_dict.stat

        with logging_context(ident='stat'):
            self._counted_logger.print(
                self.debug,
                list_value_dict={
                    'receipts processing ms': state.process_time_ms,
                    'processed neon blocks': state.neon_block_cnt,
                    'processed solana transactions': state.sol_tx_meta_cnt,
                    'processed solana instructions': state.sol_neon_ix_cnt
                },
                latest_value_dict={
                    'neon blocks': cache_stat.neon_block_cnt,
                    'neon holders': cache_stat.neon_holder_cnt,
                    'neon transactions': cache_stat.neon_tx_cnt,
                    'solana instructions': cache_stat.sol_neon_ix_cnt,
                    'indexed block slot': state.stop_block_slot,
                    'min used block slot': cache_stat.min_block_slot
                }
            )
