import multiprocessing as mp
import ctypes
import pickle

from logged_groups import logged_group

from ..indexer.indexer_db import IndexerDB
from ..common_neon.errors import PendingTxError


class NeonPendingTxInfo:
    def __init__(self, neon_sign: str, operator: str, slot: int):
        self.neon_sign = neon_sign
        self.operator = operator
        self.slot = slot

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src


@logged_group("neon.Proxy")
class MemPendingTxsDB:
    # These variables are global for class, they will be initialized one time
    BIG_SLOT = 1_000_000_000_000

    _manager = mp.Manager()

    _pending_slot = mp.Value(ctypes.c_ulonglong, BIG_SLOT)

    _pending_tx_by_hash = _manager.dict()
    _pending_slot_by_hash = _manager.dict()

    def __init__(self, db: IndexerDB):
        self._db = db

    def _set_tx(self, tx: NeonPendingTxInfo):
        data = pickle.dumps(tx)
        self._pending_tx_by_hash[tx.neon_sign] = data
        self._pending_slot_by_hash[tx.neon_sign] = tx.slot

        if self._pending_slot.value > tx.slot:
            self._pending_slot.value = tx.slot

    def _rm_finalized_txs(self, before_slot: int):
        if self._pending_slot.value > before_slot:
            return

        rm_sign_list = []
        pending_slot = self.BIG_SLOT

        # Filter tx by slot
        for sign, slot in self._pending_slot_by_hash.items():
            if slot < before_slot:
                rm_sign_list.append(sign)
            elif pending_slot > slot:
                pending_slot = slot

        self._pending_slot.value = pending_slot

        # Remove old txs
        for sign in rm_sign_list:
            del self._pending_tx_by_hash[sign]
            del self._pending_slot_by_hash[sign]

    def is_exist(self, neon_sign: str, before_slot) -> bool:
        with self._pending_slot.get_lock():
            self._rm_finalized_txs(before_slot)
            return neon_sign in self._pending_tx_by_hash

    def pend_transaction(self, tx: NeonPendingTxInfo, before_slot: int):
        executed_tx = self._db.get_tx_by_neon_sign(tx.neon_sign)
        if executed_tx:
            raise PendingTxError(f'Transaction {tx.neon_sign} is already executed')

        with self._pending_slot.get_lock():
            self._rm_finalized_txs(before_slot)

            pended_data = self._pending_tx_by_hash.get(tx.neon_sign)
            if not pended_data:
                return self._set_tx(tx)

            pended_operator = pickle.loads(pended_data).operator
            if pended_operator == tx.operator:
                self._set_tx(tx)
            else:
                raise PendingTxError(f'Transaction {tx.neon_sign} is locked ' +
                                     f'by other operator resource {pended_operator}')
