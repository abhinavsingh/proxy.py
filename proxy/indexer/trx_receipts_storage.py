import psycopg2
import os
import logging
from proxy.indexer.pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD\
    , POSTGRES_HOST, encode, decode, dummy

logger = logging.getLogger(__name__)

class TrxReceiptsStorage:
    def __init__(self, table_name, log_level = logging.DEBUG):
        self.table_name = table_name
        logger.setLevel(log_level)
        self.conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )

        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = self.conn.cursor()
        cur.execute(f'''
        CREATE TABLE IF NOT EXISTS
        {self.table_name} (
            slot        BIGINT,
            signature   VARCHAR(88),
            trx         BYTEA,
            PRIMARY KEY (slot, signature)
        )
        ''')

    def clear(self):
        cur = self.conn.cursor()
        cur.execute(f'DELETE FROM {self.table_name}')

    def size(self):
        cur = self.conn.cursor()
        cur.execute(f'SELECT COUNT(*) FROM {self.table_name}')
        rows = cur.fetchone()[0]
        return rows if rows is not None else 0

    def max_known_trx(self):
        cur = self.conn.cursor()
        cur.execute(f'SELECT slot, signature FROM {self.table_name} ORDER BY slot DESC, signature DESC LIMIT 1')
        row = cur.fetchone()
        if row is not None:
            return (row[0], row[1])
        return (0, None) #table empty - return default value

    def add_trx(self, slot, signature, trx):
        bin_trx = encode(trx)
        cur = self.conn.cursor()
        cur.execute(f'''
                INSERT INTO {self.table_name} (slot, signature, trx)
                VALUES ({slot},%s,%s)
                ON CONFLICT (slot, signature)
                DO UPDATE SET
                trx = EXCLUDED.trx
            ''',
            (signature, bin_trx)
        )

    def contains(self, slot, signature):
        cur = self.conn.cursor()
        cur.execute(f'SELECT 1 FROM {self.table_name} WHERE slot = %s AND signature = %s', (slot, signature,))
        return cur.fetchone() is not None

    def get_trxs(self, start_slot = 0, reverse = False):
        cur = self.conn.cursor()
        order = 'DESC' if reverse else 'ASC'
        cur.execute(f'SELECT slot, signature, trx FROM {self.table_name} WHERE slot >= {start_slot} ORDER BY slot {order}')
        rows = cur.fetchall()
        for row in rows:
            yield row[0], row[1], decode(row[2])
