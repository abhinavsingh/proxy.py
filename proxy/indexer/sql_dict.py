import psycopg2
from collections.abc import MutableMapping
from proxy.indexer.pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD\
    , POSTGRES_HOST, encode, decode, dummy


class SQLDict(MutableMapping):
    """Serialize an object using pickle to a binary format accepted by SQLite."""

    def __init__(self, tablename='table', bin_key=False):
        self.encode = encode
        self.decode = decode
        self.key_encode = encode if bin_key else dummy
        self.key_decode = decode if bin_key else dummy
        self.tablename = tablename + ("_bin_key" if bin_key else "")
        self.conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = self.conn.cursor()
        key_type = 'BYTEA' if bin_key else 'TEXT'
        cur.execute(f'''
                CREATE TABLE IF NOT EXISTS
                {self.tablename} (
                    key {key_type} UNIQUE,
                    value BYTEA
                )
            '''
        )

    def close(self):
        self.conn.close()

    def __len__(self):
        cur = self.conn.cursor()
        cur.execute(f'SELECT COUNT(*) FROM {self.tablename}')
        rows = cur.fetchone()[0]
        return rows if rows is not None else 0

    def iterkeys(self):
        cur = self.conn.cursor()
        cur.execute(f'SELECT key FROM {self.tablename}')
        rows = cur.fetchall()
        for row in rows:
            yield self.key_decode(row[0])

    def itervalues(self):
        cur = self.conn.cursor()
        cur.execute(f'SELECT value FROM {self.tablename}')
        rows = cur.fetchall()
        for row in rows:
            yield self.decode(row[0])

    def iteritems(self):
        cur = self.conn.cursor()
        cur.execute(f'SELECT key, value FROM {self.tablename}')
        rows = cur.fetchall()
        for row in rows:
            yield self.key_decode(row[0]), self.decode(row[1])

    def keys(self):
        return list(self.iterkeys())

    def values(self):
        return list(self.itervalues())

    def items(self):
        return list(self.iteritems())

    def __contains__(self, key):
        bin_key = self.key_encode(key)
        cur = self.conn.cursor()
        cur.execute(f'SELECT 1 FROM {self.tablename} WHERE key = %s', (bin_key,))
        return cur.fetchone() is not None

    def __getitem__(self, key):
        bin_key = self.key_encode(key)
        cur = self.conn.cursor()
        cur.execute(f'SELECT value FROM {self.tablename} WHERE key = %s', (bin_key,))
        item = cur.fetchone()
        if item is None:
            raise KeyError(key)
        return self.decode(item[0])

    def __setitem__(self, key, value):
        bin_key = self.key_encode(key)
        bin_value = self.encode(value)
        cur = self.conn.cursor()
        cur.execute(f'''
                INSERT INTO {self.tablename} (key, value)
                VALUES (%s,%s)
                ON CONFLICT (key)
                DO UPDATE SET
                value = EXCLUDED.value
            ''',
            (bin_key, bin_value)
        )

    def __delitem__(self, key):
        bin_key = self.key_encode(key)
        cur = self.conn.cursor()
        if bin_key not in self:
            raise KeyError(key)
        cur.execute(f'DELETE FROM {self.tablename} WHERE key = %s', (bin_key,))

    def __iter__(self):
        return self.iterkeys()
