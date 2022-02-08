from __future__ import annotations

import multiprocessing as mp
import ctypes
import pickle
import time
import math

from logged_groups import logged_group
from solana.rpc.api import Client as SolanaClient

from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_db import IndexerDB


BlocksManager = mp.Manager()


class BlockInfo:
    @classmethod
    def set(cls, block: SolanaBlockInfo):
        cls.slot.value = block.slot
        cls.hash.value = block.hash
        cls.height.value = block.height

    @classmethod
    def get(cls) -> SolanaBlockInfo:
        return SolanaBlockInfo(
            slot=cls.slot.value,
            hash=cls.hash.value,
            height=cls.height.value,
        )

    @classmethod
    def clear(cls):
        cls.slot.value = 0
        cls.hash.value = ''
        cls.height.value = 0


@logged_group("neon.Proxy")
class BlocksDB:
    # These variables are global for class, they will be initialized one time
    # Lock for blocks
    _blocks_lock = BlocksManager.Lock()

    # Blocks dictionaries
    _blocks_by_hash = BlocksManager.dict()
    _blocks_by_height = BlocksManager.dict()
    _blocks_by_slot = BlocksManager.dict()

    # Last requesting time of blocks from Solana node
    _last_time = BlocksManager.Value(ctypes.c_ulonglong, 0)

    class _DBLastBlockInfo(BlockInfo):
        slot = BlocksManager.Value(ctypes.c_ulonglong, 0)
        height = BlocksManager.Value(ctypes.c_ulonglong, 0)
        hash = BlocksManager.Value(ctypes.c_char_p, "")

    class _FirstBlockInfo(BlockInfo):
        slot = BlocksManager.Value(ctypes.c_ulonglong, 0)
        height = BlocksManager.Value(ctypes.c_ulonglong, 0)
        hash = BlocksManager.Value(ctypes.c_char_p, "")

    class _LastBlockInfo(BlockInfo):
        slot = BlocksManager.Value(ctypes.c_ulonglong, 0)
        height = BlocksManager.Value(ctypes.c_ulonglong, 0)
        hash = BlocksManager.Value(ctypes.c_char_p, "")

    def __init__(self, client: SolanaClient, db: IndexerDB):
        self._solana = SolanaInteractor(client)
        self._db = db

    def _rm_old_blocks(self, slot_list):
        exists_slot_list = [slot for slot in self._blocks_by_slot.keys()]
        rm_slot_list = [slot for slot in exists_slot_list if slot not in slot_list]

        for slot in rm_slot_list:
            del self._blocks_by_slot[slot]

        self._blocks_by_height.clear()
        self._blocks_by_hash.clear()

        return [slot for slot in slot_list if slot not in exists_slot_list]

    def _add_new_blocks(self, block_list):
        block_list = [block for block in block_list if block is not None]

        for data in self._blocks_by_slot.values():
            block_list.append(pickle.loads(data))

        block_list = sorted(block_list, key=lambda b: b.slot)
        height = self._DBLastBlockInfo.height.value

        self._blocks_by_slot.clear()
        for block in block_list:
            height += 1
            block.height = height
            data = pickle.dumps(block)
            self._blocks_by_slot[block.slot] = data
            self._blocks_by_hash[block.hash] = data
            self._blocks_by_height[block.height] = data

        if len(block_list):
            self._FirstBlockInfo.set(block_list[0])
            self._LastBlockInfo.set(block_list[len(block_list) - 1])
        else:
            self._FirstBlockInfo.clear()
            self._LastBlockInfo.clear()

    def _request_blocks(self):
        # 10 == 0.1 sec, when 0.4 is one block time
        now = math.ceil(time.time_ns() / 10_000_000)
        if now < self._last_time.value or (now - self._last_time.value) < 40:
            return

        db_block = self._db.get_latest_block()
        self._last_time.value = now
        self._DBLastBlockInfo.set(db_block)

        slot_list = self._solana.get_block_slot_list(db_block.slot, 100)
        if not len(slot_list):
            self.error('No confirmed block slots on Solana!')
            return

        slot_list = self._rm_old_blocks(slot_list)
        block_list = self._solana.get_block_info_list(slot_list)
        self._add_new_blocks(block_list)

    def force_request_blocks(self):
        self._last_time.value = 0

    def get_db_latest_block(self) -> SolanaBlockInfo:
        with self._blocks_lock:
            self._request_blocks()
            return self._DBLastBlockInfo.get()

    def get_latest_block(self) -> SolanaBlockInfo:
        with self._blocks_lock:
            self._request_blocks()
            return self._LastBlockInfo.get()

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        if block_height >= self._FirstBlockInfo.height.value:
            with self._blocks_lock:
                self._request_blocks()
                data = self._blocks_by_height.get(block_height)
                if data is not None:
                    return pickle.loads(data)
                if block_height >= self._FirstBlockInfo.height.value:
                    return SolanaBlockInfo()

        return self._db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        if block_slot > self._FirstBlockInfo.slot.value:
            with self._blocks_lock:
                self._request_blocks()
                data = self._blocks_by_slot.get(block_slot)
                if data:
                    return pickle.loads(data)
                if block_slot > self._FirstBlockInfo.slot.value:
                    return SolanaBlockInfo()

        return self._db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        with self._blocks_lock:
            self._request_blocks()
            data = self._blocks_by_hash.get(block_hash)
            if data:
                return pickle.loads(data)

        return self._db.get_block_by_hash(block_hash)
