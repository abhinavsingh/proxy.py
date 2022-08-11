from typing import Optional

import psycopg2.extensions

from ..common_neon.solana_neon_tx_receipt import SolTxSigSlotInfo
from ..indexer.base_db import BaseDB


class SolSigsDB(BaseDB):
    def __init__(self):
        super().__init__('solana_transaction_signatures')
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def add_sig(self, info: SolTxSigSlotInfo) -> None:
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}
                    (block_slot, signature)
                VALUES
                    (%s, %s)
                ON CONFLICT DO NOTHING
                ''',
                (info.block_slot, info.sol_sig)
            )

    def get_next_sig(self, block_slot: int) -> Optional[SolTxSigSlotInfo]:
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                SELECT signature,
                       block_slot
                  FROM {self._table_name}
                 WHERE block_slot > {block_slot}
              ORDER BY block_slot
                 LIMIT 1
            ''')
            row = cursor.fetchone()
            if row is not None:
                return SolTxSigSlotInfo(sol_sig=row[0], block_slot=row[1])
            return None

    def get_max_sig(self) -> Optional[SolTxSigSlotInfo]:
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                SELECT signature,
                       block_slot
                  FROM {self._table_name}
              ORDER BY block_slot DESC
                 LIMIT 1
            ''')
            row = cursor.fetchone()
            if row is not None:
                return SolTxSigSlotInfo(sol_sig=row[0], block_slot=row[1])
            return None
