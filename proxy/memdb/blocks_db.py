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
    BIG_SLOT = 1_000_000_000_000

    def __init__(self, blocks_db: MemBlocksDB):
        self._b = blocks_db

        self.packed_block_list = []
        self.latest_db_block_slot = 0
        self.packed_first_block = bytes()
        self.packed_latest_block = bytes()
        self.pending_block_revision = 0

        self.block_list = []
        self.first_block = SolanaBlockInfo(slot=0, height=0)
        self.latest_block = SolanaBlockInfo(slot=0, height=0)

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
        self.latest_db_block_slot = self._b.db.get_latest_block().slot
        if not self.latest_db_block_slot:
            self.latest_db_block_slot = self._b.solana.get_recent_blockslot(commitment=FINALIZED)

    def _get_solana_block_list(self) -> bool:
        slot = self.latest_db_block_slot
        slot_list = [s for s in range(slot + self.BLOCK_CACHE_LIMIT, slot - 1, -1)]
        self.block_list = self._b.solana.get_block_info_list(slot_list)
        if not len(self.block_list):
            return False

        self.latest_block = self.block_list[0]

        height = self.latest_block.height
        latest_height = self._b.get_latest_block_height()
        if latest_height > height:
            height = latest_height
        for block in self.block_list:
            block.height = height
            height -= 1

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
    _block_by_height = {}

    # Head and tail of cache
    _first_block = SolanaBlockInfo(slot=0, height=0)
    _latest_block = SolanaBlockInfo(slot=0, height=0)
    _latest_db_block_slot = 0

    def __init__(self, solana: SolanaInteractor, db: IndexerDB):
        self.db = db
        self.solana = solana
        self._update_block_dicts()
        self.debug(f'Init first version of block list {len(self._block_by_height)} ' +
                   f'first block - {self._first_block}, ' +
                   f'latest block - {self._latest_block}, ' +
                   f'latest db block slot - {self._latest_db_block_slot}')

    def _get_now(self) -> int:
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

        self._block_by_height.clear()
        self._block_by_hash.clear()

        for block in request.block_list:
            self._block_by_hash[block.hash] = block
            self._block_by_height[block.height] = block

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
        if not self._request_new_block_list():
            self._try_to_fill_blocks_from_pending_list()

    def get_latest_block(self) -> SolanaBlockInfo:
        self._update_block_dicts()
        return self._latest_block

    def get_latest_block_height(self) -> int:
        self._update_block_dicts()
        return self._latest_block.height

    def get_db_block_slot(self) -> int:
        self._update_block_dicts()
        return self._latest_db_block_slot

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        self._update_block_dicts()
        if block_height > self._first_block.height:
            return self._block_by_height.get(block_height, SolanaBlockInfo())

        return self.db.get_block_by_height(block_height)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        self._update_block_dicts()
        block = self._block_by_hash.get(block_hash)
        if block:
            return block

        return self.db.get_block_by_hash(block_hash)

    def _generate_fake_block(self, neon_res: NeonTxResultInfo) -> SolanaBlockInfo:
        data = self._pending_block_by_slot.get(neon_res.slot)
        if data:
            block = pickle.loads(data)
        else:
            latest_block = self._latest_block
            block_height = (latest_block.height or neon_res.slot) + 1
            block_time = (latest_block.time or 1)

            block = SolanaBlockInfo(
                slot=neon_res.slot,
                height=block_height,
                time=block_time,
                hash='0x' + os.urandom(32).hex(),
                parent_hash='0x' + os.urandom(32).hex(),
            )
            self.debug(f'Generate fake block {block} for {neon_res.sol_sign}')

        block.signs.append(neon_res.sol_sign)
        return block

    def submit_block(self, neon_res: NeonTxResultInfo) -> SolanaBlockInfo:
        block_list = self.solana.get_block_info_list([neon_res.slot])
        is_new_block = False
        if len(block_list):
            block = block_list[0]
            data = pickle.dumps(block)
        else:
            block = SolanaBlockInfo()
            data = None

        with self._last_time.get_lock():
            if not block.slot:
                block = self._generate_fake_block(neon_res)
                data = pickle.dumps(block)
                is_new_block = True
            else:
                is_new_block = neon_res.slot not in self._pending_block_by_slot

            if is_new_block:
                self._pending_block_by_slot[block.slot] = data
                self._pending_block_list.append(data)

                # Force updating of block dictionaries in workers
                self._pending_block_revision.value += 1

        return block
