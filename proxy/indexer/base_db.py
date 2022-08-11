from __future__ import annotations

import psycopg2
import psycopg2.extras
import psycopg2.extensions

from typing import List, Any, Optional
from logged_groups import logged_group

from .pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST
from .pg_common import encode, decode


@logged_group("neon.Indexer")
class BaseDB:
    Connection = psycopg2.extensions.connection
    Cursor = psycopg2.extensions.cursor

    def __init__(self, table_name: str):
        self._table_name = table_name
        self._blocks_table_name = 'solana_blocks'
        self._column_list: List[str] = []
        self._conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    def __del__(self):
        self._conn.close()

    @staticmethod
    def _decode_list(v: Optional[bytes]) -> List[Any]:
        return [] if not v else decode(v)

    @staticmethod
    def _encode_list(v: List[Any]) -> bytes:
        return None if (not v) or (len(v) == 0) else encode(v)

    def _insert_batch(self, cursor: BaseDB.Cursor, value_list_list: List[List[Any]]) -> None:
        assert len(self._column_list) > 0
        if len(value_list_list) == 0:
            return

        request = f'''
            INSERT INTO {self._table_name}
                ({','.join(self._column_list)})
            VALUES
                %s
            ON CONFLICT DO NOTHING;
        '''
        psycopg2.extras.execute_values(
            cursor,
            request,
            value_list_list,
            template=None,
            page_size=1000
        )

    def conn(self) -> BaseDB.Connnection:
        return self._conn

    def is_connected(self) -> bool:
        try:
            with self._conn.cursor() as cursor:
                cursor.execute('SELECT 1')
            return True
        except psycopg2.OperationalError:
            return False
