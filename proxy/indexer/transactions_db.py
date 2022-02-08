from typing import Optional

from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, NeonTxFullInfo
from ..indexer.utils import BaseDB, DBQuery, SolanaIxSignInfo


class SolanaNeonTxsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'solana_neon_transactions'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                sol_sign CHAR(88),
                neon_sign CHAR(66),
                slot BIGINT,
                idx INT,

                UNIQUE(sol_sign, neon_sign, idx),
                UNIQUE(neon_sign, sol_sign, idx)
            );"""

    def set_txs(self, neon_sign: str, used_ixs: [SolanaIxSignInfo]):

        used_ixs = set(used_ixs)
        rows = []
        for ix in used_ixs:
            rows.append((ix.sign, neon_sign, ix.slot, ix.idx))

        with self._conn.cursor() as cursor:
            cursor.executemany(f'''
                INSERT INTO {self._table_name}(sol_sign, neon_sign, slot, idx)
                VALUES(%s, %s, %s, %s) ON CONFLICT DO NOTHING''',
                rows)


class NeonTxsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)
        self._column_lst = ('neon_sign', 'from_addr', 'sol_sign', 'slot', 'block_height', 'block_hash', 'idx',
                            'nonce', 'gas_price', 'gas_limit', 'to_addr', 'contract', 'value', 'calldata',
                            'v', 'r', 's', 'status', 'gas_used', 'return_value', 'logs')
        self._sol_neon_txs_db = SolanaNeonTxsDB()

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_transactions'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                neon_sign CHAR(66),
                from_addr CHAR(42),
                sol_sign CHAR(88),
                slot BIGINT,
                block_height BIGINT,
                block_hash CHAR(66),
                idx INT,

                nonce VARCHAR,
                gas_price VARCHAR,
                gas_limit VARCHAR,
                value VARCHAR,
                gas_used VARCHAR,

                to_addr CHAR(42),
                contract CHAR(42),

                status CHAR(3),

                return_value TEXT,

                v TEXT,
                r TEXT,
                s TEXT,

                calldata TEXT,
                logs BYTEA,

                UNIQUE(neon_sign),
                UNIQUE(sol_sign, idx)
            );
            """

    def _tx_from_value(self, value) -> Optional[NeonTxFullInfo]:
        if not value:
            return None

        neon_tx = NeonTxInfo()
        neon_res = NeonTxResultInfo()

        for idx, column in enumerate(self._column_lst):
            if column in ('neon_sign', 'from_addr', 'sol_sign', 'logs'):
                pass
            elif hasattr(neon_tx, column):
                setattr(neon_tx, column, value[idx])
            elif hasattr(neon_res, column):
                setattr(neon_res, column, value[idx])
            else:
                assert False, f'Wrong usage {idx} -> {column}!'

        neon_tx.sign = value[0]
        neon_tx.addr = value[1]
        neon_res.sol_sign = value[2]
        neon_res.logs = self.decode_list(value[len(self._column_lst) - 1])

        return NeonTxFullInfo(neon_tx=neon_tx, neon_res=neon_res)

    def set_tx(self, tx: NeonTxFullInfo):
        row = [tx.neon_tx.sign, tx.neon_tx.addr, tx.neon_res.sol_sign]
        for idx, column in enumerate(self._column_lst):
            if column in ['neon_sign', 'from_addr', 'sol_sign', 'logs']:
                pass
            elif hasattr(tx.neon_tx, column):
                row.append(getattr(tx.neon_tx, column))
            elif hasattr(tx.neon_res, column):
                row.append(getattr(tx.neon_res, column))
            else:
                assert False, f'Wrong usage {idx} -> {column}!'

        row.append(self.encode_list(tx.neon_res.logs))

        cursor = self._conn.cursor()
        cursor.execute(f'''
                        INSERT INTO {self._table_name}
                            ({', '.join(self._column_lst)})
                        VALUES
                            ({', '.join(['%s' for _ in self._column_lst])})
                        ON CONFLICT DO NOTHING;
                       ''',
                       row)

        self._sol_neon_txs_db.set_txs(tx.neon_tx.sign, tx.used_ixs)

    def get_tx_by_neon_sign(self, neon_sign) -> Optional[NeonTxFullInfo]:
        return self._tx_from_value(
            self._fetchone(DBQuery(
                column_list=self._column_lst,
                key_list=[('neon_sign', neon_sign)],
                order_list=[],
            ))
        )

    def get_tx_list_by_sol_sign(self, sol_sign_list: [str]) -> [NeonTxFullInfo]:
        e = self._build_expression(DBQuery(
            column_list=self._column_lst,
            key_list=[],
            order_list=[],
        ))

        request = f'''
            SELECT {e.column_expr}
              FROM {self._table_name} AS a
             WHERE sol_sign in ({','.join(['%s' for _ in sol_sign_list])})
             LIMIT {len(sol_sign_list)}
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, sol_sign_list)
            values = cursor.fetchall()

        return [self._tx_from_value(v) for v in values]
