from __future__ import annotations

import hashlib
import copy

from enum import Enum
from typing import Iterator, List, Optional, Dict, NamedTuple, Union, Set, Deque
from logged_groups import logged_group

from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, NeonTxReceiptInfo, SolanaBlockInfo, str_fmt_object
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolNeonIxReceiptInfo, SolTxCostInfo
from ..common_neon.environment_data import SKIP_CANCEL_TIMEOUT, HOLDER_TIMEOUT


class BaseNeonIndexedObjInfo:
    def __init__(self):
        self._block_slot = 0
        self._sol_neon_ix_list: List[SolNeonIxReceiptInfo] = []
        self._sol_tx_cost_set: Set[SolTxCostInfo] = set()

    def __str__(self) -> str:
        return str_fmt_object(self)

    @property
    def block_slot(self) -> int:
        return self._block_slot

    @property
    def sol_spent(self) -> int:
        sol_spent = 0
        for tx_cost in self._sol_tx_cost_set:
            sol_spent += tx_cost.sol_spent
        return sol_spent

    @property
    def sol_tx_cnt(self) -> int:
        return len(self._sol_tx_cost_set)

    def add_sol_neon_ix(self, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        self._block_slot = max(self._block_slot, sol_neon_ix.block_slot)
        self._sol_neon_ix_list.append(sol_neon_ix)
        self._sol_tx_cost_set.add(sol_neon_ix.sol_tx_cost)

    def move_sol_neon_ix(self, indexed_obj: BaseNeonIndexedObjInfo) -> None:
        self._block_slot = max(self._block_slot, indexed_obj.block_slot)
        self._sol_neon_ix_list += indexed_obj._sol_neon_ix_list
        self._sol_tx_cost_set.update(indexed_obj._sol_tx_cost_set)
        indexed_obj._sol_neon_ix_list.clear()

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        return iter(self._sol_neon_ix_list)


class NeonAccountInfo:
    def __init__(self, neon_address: Optional[str],
                 pda_address: str,
                 code_address: Optional[str],
                 block_slot: int,
                 code: Optional[str],
                 sol_sig: Optional[str]):
        self._neon_address = neon_address
        self._pda_address = pda_address
        self._code_address = code_address
        self._block_slot = block_slot
        self._code = code
        self._sol_sig = sol_sig

    def __str__(self) -> str:
        return str_fmt_object(self)


class NeonIndexedHolderInfo(BaseNeonIndexedObjInfo):
    class DataChunk(NamedTuple):
        offset: int
        length: int
        data: bytes

        @staticmethod
        def init_empty() -> NeonIndexedHolderInfo.DataChunk:
            return NeonIndexedHolderInfo.DataChunk(offset=0, length=0, data=bytes())

        def __str__(self):
            return str_fmt_object(self._asdict())

        def is_valid(self) -> bool:
            return (self.length > 0) and (len(self.data) == self.length)

    def __init__(self, account: str):
        super().__init__()
        self._account = account
        self._data_size = 0
        self._data = bytes()

    @property
    def account(self) -> str:
        return self._account

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def data_size(self) -> int:
        return self._data_size

    def add_data_chunk(self, chunk: DataChunk) -> None:
        end_pos = chunk.offset + chunk.length
        data_len = len(self._data)
        if end_pos > data_len:
            self._data += bytes(end_pos - data_len)

        self._data = self._data[:chunk.offset] + chunk.data + self._data[end_pos:]
        self._data_size += chunk.length


class NeonIndexedTxInfo(BaseNeonIndexedObjInfo):
    class Status(Enum):
        IN_PROGRESS = 1
        CANCELED = 2
        DONE = 3

    class Key:
        def __init__(self, storage_account: str, iter_blocked_account: Iterator[str]):
            if not len(storage_account):
                self._storage_account = ''
                self._blocked_account_list = []
                self._value = ''
                return

            self._storage_account = storage_account
            self._blocked_account_list = list(iter_blocked_account)

            key_data = ':'.join([storage_account] + self._blocked_account_list)
            self._value = hashlib.sha1(key_data.encode('utf-8')).digest().hex()

        @staticmethod
        def from_ix(sol_neon_ix: SolNeonIxReceiptInfo) -> NeonIndexedTxInfo.Key:
            key = NeonIndexedTxInfo.Key(storage_account='', iter_blocked_account=iter([]))
            key._value = str(sol_neon_ix)
            return key

        def __str__(self) -> str:
            return str_fmt_object(self)

        def is_empty(self) -> bool:
            return self._value == ''

        @property
        def value(self) -> str:
            return self._value

        @property
        def storage_account(self) -> str:
            return self._storage_account

        @property
        def blocked_account_list(self) -> List[str]:
            return self._blocked_account_list

    def __init__(self, key: NeonIndexedTxInfo.Key, neon_tx: NeonTxInfo):
        super().__init__()
        self._key = key
        self._neon_receipt = NeonTxReceiptInfo(neon_tx, NeonTxResultInfo())
        self._holder_account = ''
        self._status = NeonIndexedTxInfo.Status.IN_PROGRESS

    @property
    def storage_account(self) -> str:
        return self._key.storage_account

    @property
    def holder_account(self) -> str:
        return self._holder_account

    @property
    def blocked_account_cnt(self) -> int:
        return len(self._key.blocked_account_list)

    def iter_blocked_account(self) -> Iterator[str]:
        return iter(self._key.blocked_account_list)

    @property
    def key(self) -> NeonIndexedTxInfo.Key:
        return self._key

    @property
    def neon_tx(self) -> NeonTxInfo:
        return self._neon_receipt.neon_tx

    @property
    def neon_tx_res(self) -> NeonTxResultInfo:
        return self._neon_receipt.neon_tx_res

    @property
    def status(self) -> NeonIndexedTxInfo.Status:
        return self._status

    def set_holder_account(self, holder: NeonIndexedHolderInfo) -> None:
        assert self._holder_account == ''
        self._holder_account = holder.account
        self.move_sol_neon_ix(holder)

    def set_status(self, value: NeonIndexedTxInfo.Status) -> None:
        self._status = value


@logged_group("neon.Indexer")
class NeonIndexedBlockInfo:
    _SolIDInfo = Union[SolNeonIxReceiptInfo, SolTxMetaInfo]

    def __init__(self, history_block_deque: Deque[SolanaBlockInfo]):
        self._sol_block = history_block_deque[-1]
        self._history_block_deque = history_block_deque
        self._is_completed = False

        self._neon_holder_dict: Dict[str, NeonIndexedHolderInfo] = {}
        self._neon_tx_dict: Dict[str, NeonIndexedTxInfo] = {}
        self._sol_neon_ix_dict: Dict[SolNeonIxReceiptInfo, int] = {}

        self._done_neon_tx_list: List[NeonIndexedTxInfo] = []

        self._sol_tx_cost_list: List[SolTxCostInfo] = []

        self._log_idx = 0

    def __str__(self) -> str:
        return str_fmt_object(self)

    def clone(self, history_block_deque: Deque[SolanaBlockInfo]) -> NeonIndexedBlockInfo:
        sol_block = history_block_deque[-1]
        assert sol_block.block_slot > self.block_slot

        new_block = NeonIndexedBlockInfo(history_block_deque)
        new_block._neon_holder_dict = copy.deepcopy(self._neon_holder_dict)
        new_block._neon_tx_dict = copy.deepcopy(self._neon_tx_dict)
        new_block._sol_neon_ix_dict = copy.deepcopy(self._sol_neon_ix_dict)
        return new_block

    @property
    def block_slot(self) -> int:
        return self._sol_block.block_slot

    @property
    def block_hash(self) -> str:
        return self._sol_block.block_hash

    @property
    def is_finalized(self) -> bool:
        return self._sol_block.is_finalized

    @property
    def is_completed(self) -> bool:
        return self._is_completed

    def set_finalized(self, value: bool) -> None:
        for block in self._history_block_deque:
            block.set_finalized(value)

    def finalize_history_list(self, finalized_block_slot: int) -> int:
        removed_block_cnt = 0
        while len(self._history_block_deque) and (finalized_block_slot >= self._history_block_deque[0].block_slot):
            self._history_block_deque.popleft()
            removed_block_cnt += 1
        assert len(self._history_block_deque)
        return removed_block_cnt

    def _add_sol_neon_ix(self, indexed_obj: BaseNeonIndexedObjInfo, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        d = self._sol_neon_ix_dict
        indexed_obj.add_sol_neon_ix(sol_neon_ix)
        d[sol_neon_ix] = d.get(sol_neon_ix, 0) + 1

    def _del_sol_neon_ix(self, indexed_obj: BaseNeonIndexedObjInfo, sol_id: _SolIDInfo) -> None:
        d = self._sol_neon_ix_dict
        for ix in indexed_obj.iter_sol_neon_ix():
            cnt = d.get(ix, 0) - 1
            if cnt < 0:
                error_msg = f'{sol_id} - {ix} has the negative usage counter'
                self.error(error_msg)
                raise RuntimeError(error_msg)
            elif cnt == 0:
                del d[ix]
            else:
                d[ix] = cnt

    def add_sol_tx_cost(self, sol_tx_cost: SolTxCostInfo) -> None:
        self._sol_tx_cost_list.append(sol_tx_cost)

    def get_neon_holder(self, account: str, sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedHolderInfo]:
        holder = self._neon_holder_dict.get(account)
        if holder:
            self._add_sol_neon_ix(holder, sol_neon_ix)
        return holder

    def add_neon_holder(self, account: str, sol_neon_ix: SolNeonIxReceiptInfo) -> NeonIndexedHolderInfo:
        if account in self._neon_holder_dict:
            raise RuntimeError(f'{sol_neon_ix} - the holder {account} already in use!')

        holder = NeonIndexedHolderInfo(account=account)
        self._add_sol_neon_ix(holder, sol_neon_ix)
        self._neon_holder_dict[account] = holder
        return holder

    def _del_neon_holder(self, holder: NeonIndexedHolderInfo, sol_id: _SolIDInfo) -> None:
        if not self._neon_holder_dict.pop(holder.account, None):
            self.warning(f'{sol_id} - attempt to remove the not-existent {holder}')
        else:
            self._del_sol_neon_ix(holder, sol_id)

    def fail_neon_holder(self, holder: NeonIndexedHolderInfo, sol_id: _SolIDInfo) -> None:
        self._del_neon_holder(holder, sol_id)

    def done_neon_holder(self, holder: NeonIndexedHolderInfo, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        self._del_neon_holder(holder, sol_neon_ix)

    def get_neon_tx(self, key: NeonIndexedTxInfo.Key, sol_neon_ix: SolNeonIxReceiptInfo) -> Optional[NeonIndexedTxInfo]:
        tx = self._neon_tx_dict.get(key.value)
        if tx:
            self._add_sol_neon_ix(tx, sol_neon_ix)
        return tx

    def add_neon_tx(self, key: NeonIndexedTxInfo.Key,
                    neon_tx: NeonTxInfo,
                    sol_neon_ix: SolNeonIxReceiptInfo) -> NeonIndexedTxInfo:
        if key.value in self._neon_tx_dict:
            raise RuntimeError(f'{sol_neon_ix} - the tx {key} already in use!')

        tx = NeonIndexedTxInfo(key, neon_tx)
        self._add_sol_neon_ix(tx, sol_neon_ix)
        self._neon_tx_dict[key.value] = tx
        return tx

    def _del_neon_tx(self, tx: NeonIndexedTxInfo, sol_id: _SolIDInfo) -> None:
        if tx.key.is_empty():
            pass
        elif not self._neon_tx_dict.pop(tx.key.value, None):
            self.warning(f'{sol_id} - attempt to remove the not-existent {tx}')
        else:
            self._del_sol_neon_ix(tx, sol_id)

    def fail_neon_tx(self, tx: NeonIndexedTxInfo, sol_id: _SolIDInfo) -> None:
        if tx.status not in (NeonIndexedTxInfo.Status.IN_PROGRESS, NeonIndexedTxInfo.Status.CANCELED):
            self.warning(f'{sol_id} - attempt to fail the completed tx {tx}')
            return

        self._del_neon_tx(tx, sol_id)

    def done_neon_tx(self, tx: NeonIndexedTxInfo, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        if tx.status not in (NeonIndexedTxInfo.Status.IN_PROGRESS, NeonIndexedTxInfo.Status.CANCELED):
            self.warning(f'{sol_neon_ix} - attempt to done the completed tx {tx}')
            return

        tx_idx = len(self._done_neon_tx_list)

        tx.set_status(NeonIndexedTxInfo.Status.DONE)
        tx.neon_tx_res.fill_block_info(self._sol_block, tx_idx, self._log_idx)

        self._log_idx += len(tx.neon_tx_res.log_list)

        self._done_neon_tx_list.append(tx)

    def add_neon_account(self, account: NeonAccountInfo, sol_neon_ix: SolNeonIxReceiptInfo) -> None:
        pass

    def iter_history_block(self) -> Iterator[SolanaBlockInfo]:
        return iter(self._history_block_deque)

    @property
    def history_block_cnt(self):
        return len(self._history_block_deque)

    def iter_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        return iter(self._neon_tx_dict.values())

    @property
    def neon_tx_cnt(self) -> int:
        return len(self._neon_tx_dict)

    def iter_neon_holder(self) -> Iterator[NeonIndexedHolderInfo]:
        return iter(self._neon_holder_dict.values())

    @property
    def neon_holder_cnt(self) -> int:
        return len(self._neon_holder_dict)

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        return iter(self._sol_neon_ix_dict.keys())

    @property
    def sol_neon_ix_cnt(self) -> int:
        return len(self._sol_neon_ix_dict)

    def iter_sol_tx_cost(self) -> Iterator[SolTxCostInfo]:
        return iter(self._sol_tx_cost_list)

    def iter_done_neon_tx(self) -> Iterator[NeonIndexedTxInfo]:
        return iter(self._done_neon_tx_list)

    def complete_block(self, sol_id: _SolIDInfo) -> None:
        for tx in self._done_neon_tx_list:
            self._del_neon_tx(tx, sol_id)

        self._is_completed = True
        self._done_neon_tx_list.clear()
        self._sol_tx_cost_list.clear()

        for tx in list(self.iter_neon_tx()):
            if abs(self.block_slot - tx.block_slot) > SKIP_CANCEL_TIMEOUT:
                self.debug(f'{sol_id} skip to cancel {tx}')
                self.fail_neon_tx(tx, sol_id)

        for holder in list(self.iter_neon_holder()):
            if abs(self.block_slot - holder.block_slot) > HOLDER_TIMEOUT:
                self.debug(f'{sol_id} skip the neon holder {holder}')
                self.fail_neon_holder(holder, sol_id)


@logged_group("neon.Indexer")
class NeonIndexedBlockDict:
    class Stat:
        def __init__(self, neon_holder_cnt: int, neon_tx_cnt: int,  history_block_cnt: int, sol_neon_ix_cnt: int):
            self._neon_block_cnt = 1
            self._neon_holder_cnt = neon_holder_cnt
            self._neon_tx_cnt = neon_tx_cnt
            self._history_block_cnt = history_block_cnt
            self._sol_neon_ix_cnt = sol_neon_ix_cnt
            self._min_block_slot = 0

        def __str__(self) -> str:
            return str_fmt_object(self)

        @staticmethod
        def init_empty() -> NeonIndexedBlockDict.Stat:
            return NeonIndexedBlockDict.Stat(0, 0, 0, 0)

        @staticmethod
        def from_block(neon_block: NeonIndexedBlockInfo) -> NeonIndexedBlockInfo.Stat:
            return NeonIndexedBlockDict.Stat(
                neon_holder_cnt=neon_block.neon_holder_cnt,
                neon_tx_cnt=neon_block.neon_tx_cnt,
                history_block_cnt=neon_block.history_block_cnt,
                sol_neon_ix_cnt=neon_block.sol_neon_ix_cnt
            )

        @property
        def neon_block_cnt(self) -> int:
            return self._neon_block_cnt

        @property
        def neon_holder_cnt(self) -> int:
            return self._neon_holder_cnt

        @property
        def neon_tx_cnt(self) -> int:
            return self._neon_tx_cnt

        @property
        def sol_neon_ix_cnt(self) -> int:
            return self._sol_neon_ix_cnt

        @property
        def min_block_slot(self) -> int:
            return self._min_block_slot

        def set_min_block_slot(self, block_slot: int) -> None:
            self._min_block_slot = block_slot

        def dec_history_block_cnt(self, removed_block_cnt: int) -> None:
            self._history_block_cnt -= removed_block_cnt

        def add_stat(self, src: NeonIndexedBlockDict.Stat) -> None:
            self._neon_block_cnt += src._neon_block_cnt
            self._neon_holder_cnt += src._neon_holder_cnt
            self._neon_tx_cnt += src._neon_tx_cnt
            self._history_block_cnt += src._history_block_cnt
            self._sol_neon_ix_cnt += src._sol_neon_ix_cnt

        def del_stat(self, src: NeonIndexedBlockDict.Stat) -> None:
            self._neon_block_cnt -= src._neon_block_cnt
            self._neon_holder_cnt -= src._neon_holder_cnt
            self._neon_tx_cnt -= src._neon_tx_cnt
            self._history_block_cnt -= src._history_block_cnt
            self._sol_neon_ix_cnt -= src._sol_neon_ix_cnt

    def __init__(self):
        self._neon_block_dict: Dict[int, NeonIndexedBlockInfo] = {}
        self._finalized_neon_block: Optional[NeonIndexedBlockInfo] = None
        self._stat = NeonIndexedBlockDict.Stat.init_empty()

    @property
    def finalized_neon_block(self) -> Optional[NeonIndexedBlockInfo]:
        return self._finalized_neon_block

    @property
    def stat(self) -> NeonIndexedBlockDict.Stat:
        return self._stat

    def get_neon_block(self, block_slot: int) -> Optional[NeonIndexedBlockInfo]:
        neon_block = self._neon_block_dict.get(block_slot, None)
        # Lazy cleaning of finalized history
        if (neon_block is not None) and (self._finalized_neon_block is not None):
            removed_block_cnt = neon_block.finalize_history_list(self._finalized_neon_block.block_slot)
            self._stat.dec_history_block_cnt(removed_block_cnt)
        return neon_block

    @staticmethod
    def _find_min_block_slot(neon_block: NeonIndexedBlockInfo) -> int:
        min_block_slot = neon_block.block_slot
        for ix in neon_block.iter_sol_neon_ix():
            min_block_slot = min(min_block_slot, ix.block_slot)
        return min_block_slot

    def add_neon_block(self, neon_block: NeonIndexedBlockInfo, _: SolTxMetaInfo) -> None:
        if neon_block.block_slot in self._neon_block_dict:
            return

        stat = NeonIndexedBlockDict.Stat.from_block(neon_block)
        self._stat.add_stat(stat)
        self._neon_block_dict[neon_block.block_slot] = neon_block
        # self.debug(f'{sol_tx_meta} add block {neon_block.block_slot}: {stat}')

    def finalize_neon_block(self, neon_block: NeonIndexedBlockInfo, _: SolTxMetaInfo) -> None:
        assert neon_block.block_slot in self._neon_block_dict

        if self._finalized_neon_block is not None:
            for block_slot in range(self._finalized_neon_block.block_slot, neon_block.block_slot):
                old_neon_block = self._neon_block_dict.pop(block_slot, None)
                if old_neon_block is not None:
                    stat = NeonIndexedBlockDict.Stat.from_block(old_neon_block)
                    self._stat.del_stat(stat)
                    # self.debug(f'{sol_tx_meta} del block {old_neon_block.block_slot}: {stat}')

        # self.debug(f'{sol_tx_meta} finalize block {neon_block.block_slot}')
        self._finalized_neon_block = neon_block
        self._stat.set_min_block_slot(self._find_min_block_slot(neon_block))
