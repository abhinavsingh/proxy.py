import sqlite3

class KeyValueStore(dict):
    def __init__(self, table_name, filename="local.db"):
        self.table_name = table_name
        self.conn = sqlite3.connect(filename, isolation_level=None)
        while True:
            try:
                self.conn.execute('CREATE TABLE IF NOT EXISTS {} (key text unique, value text)'.format(self.table_name))
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err
            else:
                break

    def close(self):
        self.conn.commit()
        self.conn.close()

    def __len__(self):
        rows = None
        while True:
            try:
                rows = self.conn.execute('SELECT COUNT(*) FROM {}'.format(self.table_name)).fetchone()[0]
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err
            else:
                break
        return rows if rows is not None else 0

    def iterkeys(self):
        c = self.conn.cursor()
        for row in self.conn.execute('SELECT key FROM {}'.format(self.table_name)):
            yield row[0]

    def itervalues(self):
        c = self.conn.cursor()
        for row in c.execute('SELECT value FROM {}'.format(self.table_name)):
            yield row[0]

    def iteritems(self):
        c = self.conn.cursor()
        for row in c.execute('SELECT key, value FROM {}'.format(self.table_name)):
            yield row[0], row[1]

    def keys(self):
        while True:
            try:
                return list(self.iterkeys())
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def values(self):
        while True:
            try:
                return list(self.itervalues())
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def items(self):
        while True:
            try:
                return list(self.iteritems())
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def __contains__(self, key):
        while True:
            try:
                return self.conn.execute('SELECT 1 FROM {} WHERE key = ?'.format(self.table_name), (key,)).fetchone() is not None
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def __getitem__(self, key):
        while True:
            try:
                item = self.conn.execute('SELECT value FROM {} WHERE key = ?'.format(self.table_name), (key,)).fetchone()
                if item is None:
                    raise KeyError(key)
                return item[0]
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def __setitem__(self, key, value):
        while True:
            try:
                self.conn.execute('REPLACE INTO {} (key, value) VALUES (?,?)'.format(self.table_name), (key, value))
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def __delitem__(self, key):
        while True:
            try:
                if key not in self:
                    raise KeyError(key)
                self.conn.execute('DELETE FROM {} WHERE key = ?'.format(self.table_name), (key,))
            except sqlite3.OperationalError:
                pass
            except Exception as err:
                raise err

    def __iter__(self):
        return self.iterkeys()
