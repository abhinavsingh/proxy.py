from logged_groups import logged_group
from solana.rpc.api import Client as SolanaClient
from typing import Optional

from ..indexer.indexer_db import IndexerDB

from ..common_neon.utils import NeonTxInfo, NeonTxResultInfo, NeonTxFullInfo

from ..memdb.blocks_db import BlocksDB, SolanaBlockInfo
from ..memdb.pending_tx_db import PendingTxsDB, NeonPendingTxInfo, PendingTxError
from ..memdb.transactions_db import TxsDB


@logged_group("neon.Proxy")
class MemDB:
    def __init__(self, client: SolanaClient):
        self._client = client

        self._db = IndexerDB()
        self._db.set_client(self._client)

        self._blocks_db = BlocksDB(self._client, self._db)
        self._txs_db = TxsDB(self._db)
        self._pending_tx_db = PendingTxsDB(self._db)

    def _before_slot(self) -> int:
        return self._blocks_db.get_db_latest_block().slot

    def get_latest_block_height(self) -> int:
        return self._blocks_db.get_latest_block().height

    def get_block_by_height(self, block_height: int) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_height(block_height)

    def get_full_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return self._blocks_db.get_full_block_by_slot(block_slot)

    def get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        return self._blocks_db.get_block_by_hash(block_hash)

    def pend_transaction(self, tx: NeonPendingTxInfo):
        self._pending_tx_db.pend_transaction(tx, self._before_slot())

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo):
        self._blocks_db.force_request_blocks()
        neon_res.fill_block_info(self._blocks_db.get_latest_block())
        self._txs_db.submit_transaction(neon_tx, neon_res, self._before_slot())

    def get_tx_list_by_sol_sign(self, finalized: bool, sol_sign_list: [str]) -> [NeonTxFullInfo]:
        return self._txs_db.get_tx_list_by_sol_sign(finalized, sol_sign_list, self._before_slot())

    def get_tx_by_neon_sign(self, neon_sign: str) -> Optional[NeonTxFullInfo]:
        before_slot = self._before_slot()
        is_pended_tx = self._pending_tx_db.is_exist(neon_sign, before_slot)
        return self._txs_db.get_tx_by_neon_sign(neon_sign, is_pended_tx, before_slot)

    def get_logs(self, from_block, to_block, addresses, topics, block_hash):
        return self._txs_db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def get_contract_code(self, address: str) -> str:
        return self._db.get_contract_code(address)
