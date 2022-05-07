from __future__ import annotations

import multiprocessing as mp
import traceback
import ctypes
import time
import math
import pickle
import os

from logged_groups import logged_group

from ..common_neon.utils import SolanaBlockInfo, NeonTxResultInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_db import IndexerDB

from ..environment import FINALIZED


@logged_group("neon.Proxy")
class RequestSolanaBlockList:
    BLOCK_CACHE_LIMIT = 100

    def __init__(self, blocks_db: MemBlocksDB):
        self._b = blocks_db

        self.packed_block_list = []
        self.latest_db_block_slot = 0
        self.packed_first_block = bytes()
        self.packed_latest_block = bytes()
        self.pending_block_revision = 0

        self.block_list = []
        self.first_block = SolanaBlockInfo(slot=0)
        self.latest_block = SolanaBlockInfo(slot=0)

    def execute(self) -> bool:
        try:
            self._get_latest_db_block()
            if not self._get_solana_block_list():
                return False

            self._init_packed_block_list()
            return True
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Exception on request latest block list from Solana: {err}: {err_tb}")
        return False

    def _get_latest_db_block(self):
        self.latest_db_block_slot = self._b.db.get_latest_block_slot()
        latest_solana_block_slot = self._b.solana.get_recent_blockslot(commitment=FINALIZED)
        if not self.latest_db_block_slot or (latest_solana_block_slot - self.latest_db_block_slot > 300):
            self.latest_db_block_slot = latest_solana_block_slot

    def _get_solana_block_list(self) -> bool:
        latest_db_slot = self.latest_db_block_slot
        exist_block_dict = self._b.get_block_dict(latest_db_slot)
        latest_slot = max(exist_block_dict) if len(exist_block_dict) else 0

        block_time = 0
        slot_list = []
        self.block_list = []

        max_slot = max(latest_db_slot + self.BLOCK_CACHE_LIMIT, latest_slot)
        for slot in range(max_slot, latest_db_slot - 1, -1):
            block = exist_block_dict.get(slot, SolanaBlockInfo(slot=slot, is_fake=True))
            if block.is_empty_fake():
                slot_list.append(slot)
            else:
                self.block_list.append(block)
                block_time = max(block_time, block.time)

        solana_block_list = self._b.solana.get_block_info_list(slot_list)
        for block in solana_block_list:
            if block.is_empty():
                if block.slot > latest_slot:
                    continue
                block = self._b.generate_fake_block(block.slot, block_time)
            else:
                block_time = max(block_time, block.time)
                latest_slot = max(block.slot, latest_slot)
            self.block_list.append(block)

        if not len(self.block_list):
            return False

        self.block_list.sort(key=lambda b: b.slot, reverse=True)
        self.latest_block = self.block_list[0]
        self.first_block = self.block_list[len(self.block_list) - 1]

        return len(self.block_list) > 0

    def _init_packed_block_list(self):
        self.packed_block_list = [pickle.dumps(block) for block in self.block_list]
        self.packed_first_block = pickle.dumps(self.first_block)
        self.packed_latest_block = pickle.dumps(self.latest_block)


@logged_group("neon.Proxy")
class MemBlocksDB:
    # Global blocks cache for all workers
    _manager = mp.Manager()

    _pending_block_list = _manager.list()
    _pending_block_by_slot = _manager.dict()

    _last_time = mp.Value(ctypes.c_ulonglong, 0)
    _has_active_request = mp.Value(ctypes.c_bool, False)
    _pending_block_revision = mp.Value(ctypes.c_ulong, 0)

    _pending_first_block = _manager.Value(ctypes.c_void_p, b'')
    _pending_latest_block = _manager.Value(ctypes.c_void_p, b'')
    _pending_db_block_slot = mp.Value(ctypes.c_ulonglong, 0)

    # Blocks cache for each worker
    _active_block_revision = 0

    _block_by_hash = {}
    _block_by_slot = {}

    # Head and tail of cache
    _first_block = SolanaBlockInfo(slot=0)
    _latest_block = SolanaBlockInfo(slot=0)
    _latest_db_block_slot = 0

    def __init__(self, solana: SolanaInteractor, db: IndexerDB):
        self.db = db
        self.solana = solana
        self._update_block_dicts()
        self.debug(f'Init first version of block list {len(self._block_by_slot)} ' +
                   f'first block - {self._first_block}, ' +
                   f'latest block - {self._latest_block}, ' +
                   f'latest db block slot - {self._latest_db_block_slot}')

    @staticmethod
    def _get_now() -> int:
        return math.ceil(time.time_ns() / 10_000_000)

    def _set_block_list(self, request: RequestSolanaBlockList):
        rm_block_slot_list = []
        for slot, data in self._pending_block_by_slot.items():
            if slot <= request.latest_db_block_slot:
                rm_block_slot_list.append(slot)
            else:
                block = pickle.loads(data)
                request.block_list.append(block)
                request.packed_block_list.append(data)

        for slot in rm_block_slot_list:
            del self._pending_block_by_slot[slot]

        del self._pending_block_list[:]
        self._pending_block_list.extend(request.packed_block_list)

        self._pending_first_block.value = request.packed_first_block
        self._pending_latest_block.value = request.packed_latest_block
        self._pending_db_block_slot.value = request.latest_db_block_slot

        self._pending_block_revision.value += 1

        request.pending_block_revision = self._pending_block_revision.value

    def _fill_block_dicts(self, request: RequestSolanaBlockList):
        self._active_block_revision = request.pending_block_revision

        self._first_block = request.first_block
        self._latest_block = request.latest_block
        self._latest_db_block_slot = request.latest_db_block_slot

        self._block_by_slot.clear()
        self._block_by_hash.clear()

        for block in request.block_list:
            self._block_by_hash[block.hash] = block
            self._block_by_slot[block.slot] = block

    def _start_request(self) -> bool:
        last_time = self._last_time.value
        now = self._get_now()

        # 10 == 0.1 sec, when 0.4 is one block time
        if now < last_time or (now - last_time) < 40:
            return False
        elif self._has_active_request.value:
            return False

        with self._last_time.get_lock():
            if self._has_active_request.value:
                return False
            self._has_active_request.value = True
        return True

    def _stop_request(self):
        now = self._get_now()
        with self._last_time.get_lock():
            assert self._has_active_request.value
            self._has_active_request.value = False
            self._last_time.value = now

    def _request_new_block_list(self) -> bool:
        if not self._start_request():
            return False

        request = RequestSolanaBlockList(self)
        try:
            if not request.execute():
                return False

            with self._last_time.get_lock():
                self._set_block_list(request)

            self._fill_block_dicts(request)
            return True
        finally:
            self._stop_request()

    def _restore_pending_block_list(self) -> RequestSolanaBlockList:
        request = RequestSolanaBlockList(self)

        with self._last_time.get_lock():
            request.packed_block_list = [data for data in self._pending_block_list]
            request.packed_first_block = self._pending_first_block.value
            request.packed_latest_block = self._pending_latest_block.value
            request.latest_db_block_slot = self._pending_db_block_slot.value
            request.pending_block_revision = self._pending_block_revision.value

        request.block_list = [pickle.loads(data) for data in request.packed_block_list]
        if len(request.packed_first_block):
            request.first_block = pickle.loads(request.packed_first_block)
        if len(request.packed_latest_block):
            request.latest_block = pickle.loads(request.packed_latest_block)
        return request

    def _try_to_fill_blocks_from_pending_list(self):
        if self._pending_block_revision.value <= self._active_block_revision:
            return

        request = self._restore_pending_block_list()
        self._fill_block_dicts(request)

    def _update_block_dicts(self):
        self._try_to_fill_blocks_from_pending_list()
        self._request_new_block_list()

    def get_block_dict(self, from_slot: int) -> {}:
        return {slot: block for slot, block in self._block_by_slot.items() if slot > from_slot}

    def get_latest_block(self) -> SolanaBlockInfo:
        self._update_block_dicts()
        return self._latest_block

    def get_latest_block_slot(self) -> int:
        self._update_block_dicts()
        return self._latest_block.slot

    def get_staring_block_slot(self) -> int:
        return self.db.get_starting_block().slot

    def get_db_block_slot(self) -> int:
        self._update_block_dicts()
        return self._latest_db_block_slot

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        self._update_block_dicts()
        if block_slot > self._first_block.slot:
            return self._block_by_slot.get(block_slot, SolanaBlockInfo(slot=block_slot))

        block = self.db.get_full_block_by_slot(block_slot)
        if block.is_empty():
            block = self.generate_fake_block(block.slot, self._latest_block.time)
        return block

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        self._update_block_dicts()
        block = self._block_by_hash.get(block_hash)
        if block:
            return block

        return self.db.get_block_by_hash(block_hash)

    @staticmethod
    def generate_fake_block(block_slot: int, block_time=1) -> SolanaBlockInfo:
        def slot_hash(slot: int):
            hex_num = hex(slot)[2:]
            num_len = len(hex_num)
            hex_num = '00' + hex_num.rjust(((num_len >> 1) + (num_len % 2)) << 1, '0')
            return '0x' + hex_num.rjust(64, 'f')
        hash = slot_hash(block_slot)
        # TODO: return predictable information about block time
        return SolanaBlockInfo(
            slot=block_slot,
            time=(block_time or 1),
            hash=hash,
            # return the prev block's computed hash if the block is not the first block
            # if the block is the first block (0x0) -- then just return the hash of this block itself
            parent_hash=slot_hash(block_slot - 1) if block_slot > 0 else hash,
            is_fake=True
        )

    def submit_block(self, neon_res: NeonTxResultInfo) -> SolanaBlockInfo:
        self._try_to_fill_blocks_from_pending_list()

        data = None
        block = self._block_by_slot.get(neon_res.slot, SolanaBlockInfo(slot=neon_res.slot, is_fake=True))
        # if block doesn't exist, or it's a fake block without signatures
        if block.is_empty_fake():
            block = self.solana.get_block_info(neon_res.slot)
            if not block.is_empty():
                data = pickle.dumps(block)

        with self._last_time.get_lock():
            # get the latest version of the fake block with signatures
            latest_data = self._pending_block_by_slot.get(neon_res.slot)
            if latest_data:
                block = pickle.loads(latest_data)
                data = None

            # self.solana.get_block_info() returns empty block, and there is no block in the cache
            if block.is_empty():
                block = self.generate_fake_block(neon_res.slot, self._latest_block.time)

            if block.is_fake:
                block.signs.append(neon_res.sol_sign)
                data = pickle.dumps(block)

            if not data:
                return block

            if self._latest_block.slot < block.slot:
                self._pending_latest_block.value = data

                # generate list of fake blocks
                if self._latest_block.slot:
                    for slot in range(self._latest_block.slot + 1, block.slot):
                        fake_block = self.generate_fake_block(slot, self._latest_block.time)
                        fake_data = pickle.dumps(fake_block)
                        self._pending_block_list.append(fake_data)

            self._pending_block_by_slot[block.slot] = data
            self._pending_block_list.append(data)

            # Force updating of block dictionaries in other workers
            self._pending_block_revision.value += 1

        return block
