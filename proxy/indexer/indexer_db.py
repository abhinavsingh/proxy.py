from logged_groups import logged_group
from typing import Optional, List, Iterator

from ..indexer.solana_blocks_db import SolBlocksDB, SolanaBlockInfo
from ..indexer.neon_txs_db import NeonTxsDB
from ..indexer.solana_neon_txs_db import SolNeonTxsDB
from ..indexer.neon_tx_logs_db import NeonTxLogsDB
from ..indexer.solana_tx_costs_db import SolTxCostsDB
from ..indexer.sql_dict import SQLDict
from ..indexer.base_db import BaseDB
from ..indexer.indexed_objects import NeonIndexedBlockInfo

from ..common_neon.utils import NeonTxReceiptInfo


@logged_group("neon.Indexer")
class IndexerDB:
    def __init__(self):
        self._sol_blocks_db = SolBlocksDB()
        self._sol_tx_costs_db = SolTxCostsDB()
        self._neon_txs_db = NeonTxsDB()
        self._sol_neon_txs_db = SolNeonTxsDB()
        self._neon_tx_logs_db = NeonTxLogsDB()

        self._db_list = [
            self._sol_blocks_db,
            self._sol_tx_costs_db,
            self._neon_txs_db,
            self._sol_neon_txs_db,
            self._neon_tx_logs_db
        ]

        self._constants_db = SQLDict(tablename="constants")
        for k in ['min_receipt_block_slot', 'latest_block_slot', 'starting_block_slot', 'finalized_block_slot']:
            if k not in self._constants_db:
                self._constants_db[k] = 0

        self._starting_block = SolanaBlockInfo(block_slot=0)
        self._latest_block_slot = self.get_latest_block_slot()
        self._finalized_block_slot = self.get_finalized_block_slot()
        self._min_receipt_block_slot = self.get_min_receipt_block_slot()

    def status(self) -> bool:
        return self._neon_tx_logs_db.is_connected()

    def submit_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        with self._sol_blocks_db.conn() as conn:
            with conn.cursor() as cursor:
                self._sol_blocks_db.set_block_list(cursor, neon_block.iter_history_block())
                if neon_block.is_finalized:
                    self._finalize_block(cursor, neon_block)
                self._neon_txs_db.set_tx_list(cursor, neon_block.iter_done_neon_tx())
                self._sol_neon_txs_db.set_tx_list(cursor, neon_block.iter_done_neon_tx())
                self._neon_tx_logs_db.set_tx_list(cursor, neon_block.iter_done_neon_tx())
                self._sol_tx_costs_db.set_cost_list(cursor, neon_block.iter_sol_tx_cost())

        if self.get_starting_block().block_slot == 0:
            self._constants_db['starting_block_slot'] = neon_block.block_slot

        if neon_block.is_finalized:
            self._set_finalized_block_slot(neon_block.block_slot)

    def _finalize_block(self, cursor: BaseDB.Cursor, neon_block: NeonIndexedBlockInfo) -> None:
        block_slot_list = [block.block_slot for block in neon_block.iter_history_block()]
        for db in self._db_list:
            db.finalize_block_list(cursor, self._finalized_block_slot, block_slot_list)

    def finalize_block(self, neon_block: NeonIndexedBlockInfo) -> None:
        with self._sol_blocks_db.conn() as conn:
            with conn.cursor() as cursor:
                self._finalize_block(cursor, neon_block)

        self._set_finalized_block_slot(neon_block.block_slot)

    def _set_finalized_block_slot(self, block_slot: int) -> None:
        self._finalized_block_slot = block_slot
        self._constants_db['finalized_block_slot'] = block_slot
        self._set_latest_block_slot(block_slot)

    def _set_latest_block_slot(self, block_slot: int) -> None:
        if self._latest_block_slot > block_slot:
            return
        self._latest_block_slot = block_slot
        self._constants_db['latest_block_slot'] = block_slot

    def activate_block_list(self, iter_neon_block: Iterator[NeonIndexedBlockInfo]) -> None:
        block_slot_list = [b.block_slot for n in iter_neon_block for b in n.iter_history_block() if not n.is_finalized]
        if not len(block_slot_list):
            return

        with self._sol_blocks_db.conn() as conn:
            with conn.cursor() as cursor:
                self._sol_blocks_db.activate_block_list(cursor, self._finalized_block_slot, block_slot_list)
        self._set_latest_block_slot(block_slot_list[-1])

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return self._sol_blocks_db.get_block_by_slot(block_slot, self.get_latest_block_slot())

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        return self._sol_blocks_db.get_block_by_hash(block_hash, self.get_latest_block_slot())

    def get_latest_block(self) -> SolanaBlockInfo:
        block_slot = self.get_latest_block_slot()
        if block_slot == 0:
            return SolanaBlockInfo(block_slot=0)
        return self.get_block_by_slot(block_slot)

    def get_latest_block_slot(self) -> int:
        return self._constants_db['latest_block_slot']

    def get_finalized_block_slot(self) -> int:
        return self._constants_db['finalized_block_slot']

    def get_starting_block(self) -> SolanaBlockInfo:
        if self._starting_block.block_slot != 0:
            return self._starting_block

        block_slot = self._constants_db['starting_block_slot']
        if block_slot == 0:
            return SolanaBlockInfo(block_slot=0)
        self._starting_block = self.get_block_by_slot(block_slot)
        return self._starting_block

    def get_starting_block_slot(self) -> int:
        return self.get_starting_block().block_slot

    def get_min_receipt_block_slot(self) -> int:
        return self._constants_db['min_receipt_block_slot']

    def set_min_receipt_block_slot(self, block_slot: int) -> None:
        if self._min_receipt_block_slot >= block_slot:
            return

        self._min_receipt_block_slot = block_slot
        self._constants_db['min_receipt_block_slot'] = block_slot

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        return self._neon_tx_logs_db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_tx_list_by_block_slot(self, block_slot: int) -> List[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_list_by_block_slot(block_slot)

    def get_tx_by_neon_sig(self, neon_sig: str) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_neon_sig(neon_sig)

    def get_tx_by_block_slot_tx_idx(self, block_slot: int, tx_idx: int) -> Optional[NeonTxReceiptInfo]:
        return self._neon_txs_db.get_tx_by_block_slot_tx_idx(block_slot, tx_idx)

    def get_sol_sig_list_by_neon_sig(self, neon_sig: str) -> List[str]:
        return self._sol_neon_txs_db.get_sol_sig_list_by_neon_sig(neon_sig)
