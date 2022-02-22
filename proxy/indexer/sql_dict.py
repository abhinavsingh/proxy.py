from collections.abc import MutableMapping
from proxy.indexer.pg_common import encode, decode, dummy
from proxy.indexer.base_db import BaseDB


class SQLDict(MutableMapping, BaseDB):
    """Serialize an object using pickle to a binary format accepted by SQLite."""

    def __init__(self, tablename='table', bin_key=False):
        self.bin_key = bin_key
        self.encode = encode
        self.decode = decode
        self.key_encode = encode if self.bin_key else dummy
        self.key_decode = decode if self.bin_key else dummy
        self._table_name = tablename + ("_bin_key" if self.bin_key else "")
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        key_type = 'BYTEA' if self.bin_key else 'TEXT'
        return f'''
                CREATE TABLE IF NOT EXISTS
                {self._table_name} (
                    key {key_type} UNIQUE,
                    value BYTEA
                )
            '''

    def __len__(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT COUNT(*) FROM {self._table_name}')
            rows = cur.fetchone()[0]
            return rows if rows is not None else 0

    def iterkeys(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT key FROM {self._table_name}')
            rows = cur.fetchall()
            for row in rows:
                yield self.key_decode(row[0])

    def itervalues(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT value FROM {self._table_name}')
            rows = cur.fetchall()
            for row in rows:
                yield self.decode(row[0])

    def iteritems(self):
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT key, value FROM {self._table_name}')
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
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT 1 FROM {self._table_name} WHERE key = %s', (bin_key,))
            return cur.fetchone() is not None

    def __getitem__(self, key):
        bin_key = self.key_encode(key)
        with self._conn.cursor() as cur:
            cur.execute(f'SELECT value FROM {self._table_name} WHERE key = %s', (bin_key,))
            item = cur.fetchone()
            if item is None:
                raise KeyError(key)
            return self.decode(item[0])

    def __setitem__(self, key, value):
        bin_key = self.key_encode(key)
        bin_value = self.encode(value)
        with self._conn.cursor() as cur:
            cur.execute(f'''
                    INSERT INTO {self._table_name} (key, value)
                    VALUES (%s,%s)
                    ON CONFLICT (key)
                    DO UPDATE SET
                    value = EXCLUDED.value
                ''',
                (bin_key, bin_value)
            )

    def __delitem__(self, key):
        bin_key = self.key_encode(key)
        with self._conn.cursor() as cur:
            if bin_key not in self:
                raise KeyError(key)
            cur.execute(f'DELETE FROM {self._table_name} WHERE key = %s', (bin_key,))

    def __iter__(self):
        return self.iterkeys()
