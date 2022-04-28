from proxy.environment import INDEXER_RECEIPTS_COUNT_LIMIT
from proxy.indexer.pg_common import encode, decode
from proxy.indexer.base_db import BaseDB


class TxReceiptsStorage(BaseDB):
    def __init__(self, table_name):
        BaseDB.__init__(self, table_name)

    def clear(self):
        with self._conn.cursor() as cur:
            cur.execute(f'DELETE FROM {self._table_name}')

    def size(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) FROM {self._table_name}')
            rows = cur.fetchone()[0]
            return rows if rows is not None else 0

    def max_known_tx(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT slot, signature FROM {self._table_name} ORDER BY slot DESC, tx_idx ASC LIMIT 1')
            row = cur.fetchone()
            if row is not None:
                return row[0], row[1]
            return 0, None  # table empty - return default value

    def add_tx(self, slot, tx_idx, signature, tx):
        bin_tx = encode(tx)
        with self._conn.cursor() as cur:
            cur.execute(f'''
                    INSERT INTO {self._table_name} (slot, tx_idx, signature, tx)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (slot, signature)
                    DO UPDATE SET
                    tx = EXCLUDED.tx
                ''',
                (slot, tx_idx, signature, bin_tx)
            )

    def contains(self, slot, signature):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT 1 FROM {self._table_name} WHERE slot = %s AND signature = %s', (slot, signature,))
            return cur.fetchone() is not None

    def get_txs(self, start_slot=0, stop_slot=0):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT MIN(slot) FROM {self._table_name} WHERE slot > %s', (start_slot,))
            min_slot_row = cur.fetchone()
            min_slot = (min_slot_row[0] if min_slot_row and min_slot_row[0] else 0)

            cur.execute(f'''
                    SELECT MAX(t.slot) FROM (
                            SELECT slot FROM {self._table_name}
                             WHERE slot > %s
                             ORDER BY slot
                             LIMIT {INDEXER_RECEIPTS_COUNT_LIMIT}
                        ) AS t
                ''',
                (start_slot,))
            limit_slot_row = cur.fetchone()
            limit_slot = (limit_slot_row[0] if limit_slot_row and limit_slot_row[0] else 0)

            limit_slot = max(min_slot, limit_slot, start_slot + 1)
            if stop_slot > 0:
                limit_slot = min(stop_slot, limit_slot)

            cur.execute(f'''
                    SELECT slot, signature, tx FROM {self._table_name}
                     WHERE slot >= %s AND slot <= %s
                     ORDER BY slot ASC, tx_idx DESC
                ''',
                (start_slot, limit_slot,))
            rows = cur.fetchall()

            for row in rows:
                yield int(row[0]), row[1], decode(row[2])
