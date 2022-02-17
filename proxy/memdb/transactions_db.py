import multiprocessing as mp
import pickle
import ctypes

from typing import Optional
from logged_groups import logged_group

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo, SolanaBlockInfo

from ..indexer.indexer_db import IndexerDB


@logged_group("neon.Proxy")
class MemTxsDB:
    BIG_SLOT = 1_000_000_000_000

    _manager = mp.Manager()

    _tx_slot = mp.Value(ctypes.c_ulonglong, BIG_SLOT)

    _tx_by_neon_sign = _manager.dict()
    _slot_by_neon_sign = _manager.dict()
    _tx_by_sol_sign = _manager.dict()
    _slot_by_sol_sign = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _rm_finalized_txs(self, before_slot: int):
        if self._tx_slot.value > before_slot:
            return

        rm_neon_sign_list = []
        tx_slot = self.BIG_SLOT
        for sign, slot in self._slot_by_neon_sign.items():
            if slot <= before_slot:
                rm_neon_sign_list.append(sign)
            elif tx_slot > slot:
                tx_slot = slot
        self._tx_slot.value = tx_slot

        rm_sol_sign_list = [sign for sign, slot in self._slot_by_sol_sign.items() if slot <= before_slot]

        for neon_sign, sol_sign in zip(rm_neon_sign_list, rm_sol_sign_list):
            del self._tx_by_neon_sign[neon_sign]
            del self._slot_by_neon_sign[neon_sign]

            del self._tx_by_sol_sign[sol_sign]
            del self._slot_by_sol_sign[sol_sign]

    def get_tx_list_by_sol_sign(self, finalized, sol_sign_list: [str], before_slot: int) -> [NeonTxFullInfo]:
        if finalized:
            return self._db.get_tx_list_by_sol_sign(sol_sign_list)

        tx_list = []
        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)
            for sol_sign in sol_sign_list:
                data = self._tx_by_sol_sign.get(sol_sign)
                if data:
                    tx_list.append(pickle.loads(data))
        return tx_list

    def get_tx_by_neon_sign(self, neon_sign: str, is_pended_tx: bool, before_slot: int) -> Optional[NeonTxFullInfo]:
        if not is_pended_tx:
            return self._db.get_tx_by_neon_sign(neon_sign)

        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)
            data = self._tx_by_neon_sign.get(neon_sign)
            if data:
                return pickle.loads(data)
        return None

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        def _has_address(src_addresses, dst_address):
            return dst_address in src_addresses

        def _has_topics(src_topics, dst_topics):
            for topic in src_topics:
                if topic in dst_topics:
                    return True
            return False

        result_list = []
        with self._tx_slot.get_lock():
            for data in self._tx_by_neon_sign.values():
                tx = pickle.loads(data)
                if from_block and tx.neon_res.block_height < from_block:
                    continue
                if to_block and tx.neon_res.block_height > to_block:
                    continue
                if block_hash and tx.neon_res.block_hash != block_hash:
                    continue
                for log in tx.neon_res.logs:
                    if len(addresses) and (not _has_address(addresses, log['address'])):
                        continue
                    if len(topics) and (not _has_topics(topics, log['topics'])):
                        continue
                    result_list.append(log)

        return result_list + self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, before_slot: int):
        tx = NeonTxFullInfo(neon_tx=neon_tx, neon_res=neon_res)
        data = pickle.dumps(tx)

        with self._tx_slot.get_lock():
            self._rm_finalized_txs(before_slot)

            self._tx_by_neon_sign[tx.neon_tx.sign] = data
            self._slot_by_neon_sign[tx.neon_tx.sign] = tx.neon_res.slot

            self._tx_by_sol_sign[tx.neon_res.sol_sign] = data
            self._slot_by_sol_sign[tx.neon_res.sol_sign] = tx.neon_res.slot

            if self._tx_slot.value > tx.neon_res.slot:
                self._tx_slot.value = tx.neon_res.slot
