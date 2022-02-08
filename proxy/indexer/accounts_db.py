from ..indexer.utils import BaseDB, DBQuery
from ..common_neon.utils import str_fmt_object


class NeonAccountInfo:
    def __init__(self, neon_account: str = None, pda_account: str = None, code_account: str = None, slot: int = 0, code: str = None):
        self.neon_account = neon_account
        self.pda_account = pda_account
        self.code_account = code_account
        self.slot = slot
        self.code = code

    def __str__(self):
        return str_fmt_object(self)


class NeonAccountDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_accounts'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                neon_account CHAR(42),
                pda_account VARCHAR(50),
                code_account VARCHAR(50),
                slot BIGINT,
                code TEXT,

                UNIQUE(pda_account, code_account)
            );"""

    def set_acc_by_request(self, neon_account: str, pda_account: str, code_account: str, code: str):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}(neon_account, pda_account, code_account, slot, code)
                VALUES(%s, %s, %s, %s, %s)
                ON CONFLICT (pda_account, code_account) DO UPDATE
                SET
                    code=EXCLUDED.code
                ;
                ''',
                (neon_account, pda_account, code_account, 0, code))

    def set_acc_indexer(self, neon_account: str, pda_account: str, code_account: str, slot: int):
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}(neon_account, pda_account, code_account, slot)
                VALUES(%s, %s, %s, %s)
                ON CONFLICT (pda_account, code_account) DO UPDATE
                SET
                    slot=EXCLUDED.slot
                ;
                ''',
                (neon_account, pda_account, code_account, slot))

    def _acc_from_value(self, value) -> NeonAccountInfo:
        self.debug(f"accounts db returned {value}")

        if not value:
            return NeonAccountInfo()

        return NeonAccountInfo(
            neon_account=value[0],
            pda_account=value[1],
            code_account=value[2],
            slot=value[3],
            code=value[4]
        )

    def get_account_info(self, account) -> NeonAccountInfo:
        return self._acc_from_value(
            self._fetchone(DBQuery(
                column_list=['neon_account', 'pda_account', 'code_account', 'slot', 'code'],
                key_list=[('neon_account', account)],
                order_list=['slot desc']
            ))
        )
