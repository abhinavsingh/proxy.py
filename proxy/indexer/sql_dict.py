import psycopg2
import os
import logging
from collections.abc import MutableMapping

POSTGRES_DB = os.environ.get("POSTGRES_DB", "neon-db")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "neon-proxy")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "neon-proxy-pass")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")

try:
    from cPickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL
except ImportError:
    from pickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def encode(obj):
    """Serialize an object using pickle to a binary format accepted by SQLite."""
    return psycopg2.Binary(dumps(obj, protocol=PICKLE_PROTOCOL))


def decode(obj):
    """Deserialize objects retrieved from SQLite."""
    return loads(bytes(obj))


class SQLDict(MutableMapping):
    """Serialize an object using pickle to a binary format accepted by SQLite."""

    def __init__(self, tablename='table'):
        self.encode = encode
        self.decode = decode
        self.tablename = tablename
        self.conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = self.conn.cursor()
        cur.execute('''
                CREATE TABLE IF NOT EXISTS
                {} (
                    key TEXT UNIQUE,
                    value BYTEA
                )
            '''.format(self.tablename)
        )

    def close(self):
        self.conn.close()

    def __len__(self):
        cur = self.conn.cursor()
        cur.execute('SELECT COUNT(*) FROM {}'.format(self.tablename))
        rows = cur.fetchone()[0]
        return rows if rows is not None else 0

    def iterkeys(self):
        cur = self.conn.cursor()
        cur.execute('SELECT key FROM {}'.format(self.tablename))
        rows = cur.fetchall()
        for row in rows:
            yield row[0]

    def itervalues(self):
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM {}'.format(self.tablename))
        rows = cur.fetchall()
        for value in rows:
            yield self.decode(value[0])

    def iteritems(self):
        cur = self.conn.cursor()
        cur.execute('SELECT key, value FROM {}'.format(self.tablename))
        rows = cur.fetchall()
        for row in rows:
            yield row[0], self.decode(row[1])

    def keys(self):
        return list(self.iterkeys())

    def values(self):
        return list(self.itervalues())

    def items(self):
        return list(self.iteritems())

    def __contains__(self, key):
        cur = self.conn.cursor()
        cur.execute('SELECT 1 FROM {} WHERE key = %s'.format(self.tablename), (key,))
        return cur.fetchone() is not None

    def __getitem__(self, key):
        cur = self.conn.cursor()
        cur.execute('SELECT value FROM {} WHERE key = %s'.format(self.tablename), (key,))
        item = cur.fetchone()
        if item is None:
            raise KeyError(key)
        return self.decode(item[0])

    def __setitem__(self, key, value):
        cur = self.conn.cursor()
        cur.execute('''
                INSERT INTO {} (key, value)
                VALUES (%s,%s)
                ON CONFLICT (key)
                DO UPDATE SET
                value = EXCLUDED.value
            '''.format(self.tablename),
            (key, self.encode(value))
        )

    def __delitem__(self, key):
        cur = self.conn.cursor()
        if key not in self:
            raise KeyError(key)
        cur.execute('DELETE FROM {} WHERE key = %s'.format(self.tablename), (key,))

    def __iter__(self):
        return self.iterkeys()
