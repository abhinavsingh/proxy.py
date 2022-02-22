from typing import Optional

from ..indexer.base_db import BaseDB, DBQuery
from ..common_neon.utils import SolanaBlockInfo


class SolanaBlocksDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)
        self._column_lst = ('slot', 'hash')
        self._full_column_lst = ('slot', 'hash', 'parent_hash', 'blocktime', 'signatures')

    def _create_table_sql(self) -> str:
        self._table_name = 'solana_block'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                slot BIGINT,
                hash CHAR(66),

                parent_hash CHAR(66),
                blocktime BIGINT,
                signatures BYTEA,

                UNIQUE(slot),
                UNIQUE(hash)
            );
            """

    def _block_from_value(self, slot: Optional[int], values: []) -> SolanaBlockInfo:
        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            finalized=True,
            slot=values[0],
            hash=values[1],
        )

    def _full_block_from_value(self, slot: Optional[int], values: []) -> SolanaBlockInfo:
        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            finalized=True,
            slot=values[0],
            hash=values[1],
            parent_hash=values[2],
            time=values[3],
            signs=self.decode_list(values[4])
        )

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        q = DBQuery(column_list=self._column_lst, key_list=[('slot', block_slot)], order_list=[])
        return self._block_from_value(block_slot, self._fetchone(q))

    def get_full_block_by_slot(self, block_slot) -> SolanaBlockInfo:
        q = DBQuery(column_list=self._full_column_lst, key_list=[('slot', block_slot)], order_list=[])
        return self._block_from_value(block_slot, self._fetchone(q))

    def get_block_by_hash(self, block_hash) -> SolanaBlockInfo:
        q = DBQuery(column_list=self._column_lst, key_list=[('block_hash', block_hash)], order_list=[])
        return self._block_from_value(None, self._fetchone(q))

    def set_block(self, block: SolanaBlockInfo):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}
                ({', '.join(self._full_column_lst)})
                VALUES
                ({', '.join(['%s' for _ in range(len(self._full_column_lst))])})
                ON CONFLICT DO NOTHING;
                ''',
                (block.slot, block.hash, block.parent_hash, block.time, self.encode_list(block.signs)))
