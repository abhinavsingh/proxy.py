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

    def get_txs(self, start_slot=0):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT slot, signature, tx FROM {self._table_name}' +
                        f' WHERE slot >= {start_slot} ORDER BY slot ASC, tx_idx DESC')
            rows = cur.fetchall()
            for row in rows:
                yield int(row[0]), row[1], decode(row[2])
