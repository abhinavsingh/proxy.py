from proxy.indexer.pg_common import encode, decode
from proxy.indexer.utils import BaseDB


class TrxReceiptsStorage(BaseDB):
    def __init__(self, table_name):
        self._table_name = table_name
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        return f'''
        CREATE TABLE IF NOT EXISTS {self._table_name} (
            slot        BIGINT,
            signature   VARCHAR(88),
            trx         BYTEA,
            PRIMARY KEY (slot, signature)
        );
        '''

    def clear(self):
        with self._conn.cursor() as cur:
            cur.execute(f'DELETE FROM {self._table_name}')

    def size(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) FROM {self._table_name}')
            rows = cur.fetchone()[0]
            return rows if rows is not None else 0

    def max_known_trx(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT slot, signature FROM {self._table_name} ORDER BY slot DESC, signature DESC LIMIT 1')
            row = cur.fetchone()
            if row is not None:
                return (row[0], row[1])
            return (0, None) #table empty - return default value

    def add_trx(self, slot, signature, trx):
        bin_trx = encode(trx)
        with self._conn.cursor() as cur:
            cur.execute(f'''
                    INSERT INTO {self._table_name} (slot, signature, trx)
                    VALUES ({slot},%s,%s)
                    ON CONFLICT (slot, signature)
                    DO UPDATE SET
                    trx = EXCLUDED.trx
                ''',
                (signature, bin_trx)
            )

    def contains(self, slot, signature):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT 1 FROM {self._table_name} WHERE slot = %s AND signature = %s', (slot, signature,))
            return cur.fetchone() is not None

    def get_trxs(self, start_slot = 0, reverse = False):
        order = 'DESC' if reverse else 'ASC'
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT slot, signature, trx FROM {self._table_name} WHERE slot >= {start_slot} ORDER BY slot {order}')
            rows = cur.fetchall()
            for row in rows:
                yield int(row[0]), row[1], decode(row[2])
