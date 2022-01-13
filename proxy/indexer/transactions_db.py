from proxy.indexer.pg_common import encode, decode
from .utils import BaseDB, SolanaIxSignInfo, NeonTxResultInfo, NeonTxInfo, str_fmt_object
from .blocks_db import SolanaBlockDBInfo


class NeonTxDBInfo:
    def __init__(self, neon_tx=NeonTxInfo(), neon_res=NeonTxResultInfo(), block=SolanaBlockDBInfo(), used_ixs=[]):
        self.neon_tx = neon_tx
        self.neon_res = neon_res
        self.used_ixs = used_ixs
        self.block = block

    def __str__(self):
        return str_fmt_object(self)


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

        cursor = self._conn.cursor()
        cursor.executemany(f'''
            INSERT INTO {self._table_name}(sol_sign, neon_sign, slot, idx)
            VALUES(%s, %s, %s, %s) ON CONFLICT DO NOTHING''',
            rows)


class NeonTxsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)
        self._column_lst =  ('neon_sign', 'from_addr', 'sol_sign', 'slot', 'finalized', 'idx',
                             'nonce', 'gas_price', 'gas_limit', 'to_addr', 'contract', 'value', 'calldata', 'v', 'r', 's',
                             'status', 'gas_used', 'return_value', 'logs')
        self._sol_neon_txs_db = SolanaNeonTxsDB()

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_transactions'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                neon_sign CHAR(66),
                from_addr CHAR(42),
                sol_sign CHAR(88),
                slot BIGINT,
                finalized BOOLEAN,
                idx INT,

                nonce BIGINT,
                gas_price BIGINT,
                gas_limit BIGINT,
                value BIGINT,
                gas_used BIGINT,

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
            CREATE INDEX IF NOT EXISTS {self._table_name}_finalized ON {self._table_name}(slot, finalized);
            """

    def _tx_from_value(self, value):
        if not value:
            return None

        neon_tx = NeonTxInfo()
        neon_res = NeonTxResultInfo()
        block = SolanaBlockDBInfo()

        for idx, column in enumerate(self._column_lst):
            if column in ('neon_sign', 'from_addr', 'sol_sign', 'logs'):
                pass
            elif hasattr(neon_tx, column):
                setattr(neon_tx, column, value[idx])
            elif hasattr(neon_res, column):
                setattr(neon_res, column, value[idx])
            elif hasattr(block, column):
                setattr(block, column, value[idx])
            else:
                assert False, f'Wrong usage {idx} -> {column}!'

        neon_tx.sign = value[0]
        neon_tx.addr = value[1]
        neon_res.sol_sign = value[2]
        neon_res.logs = decode(value[len(self._column_lst) - 1])

        block.slot = neon_res.slot

        return NeonTxDBInfo(neon_tx=neon_tx, neon_res=neon_res, block=block)

    def set_tx(self, tx: NeonTxDBInfo):
        row = [tx.neon_tx.sign, tx.neon_tx.addr, tx.neon_res.sol_sign]
        for idx, column in enumerate(self._column_lst):
            if column in ['neon_sign', 'from_addr', 'sol_sign', 'logs']:
                pass
            elif hasattr(tx.neon_tx, column):
                row.append(getattr(tx.neon_tx, column))
            elif hasattr(tx.neon_res, column):
                row.append(getattr(tx.neon_res, column))
            elif hasattr(tx.block, column):
                row.append(getattr(tx.block, column))
            else:
                assert False, f'Wrong usage {idx} -> {column}!'

        row.append(encode(tx.neon_res.logs))

        cursor = self._conn.cursor()
        cursor.execute(f'''
                       INSERT INTO {self._table_name}
                       ({', '.join(self._column_lst)})
                       VALUES
                       ({', '.join(['%s' for _ in range(len(self._column_lst))])})
                       ON CONFLICT DO NOTHING
                       ''',
                       row)

        self._sol_neon_txs_db.set_txs(tx.neon_tx.sign, tx.used_ixs)

    def del_not_finalized(self, from_slot: int, to_slot: int):
        cursor = self._conn.cursor()
        cursor.execute(f'DELETE FROM {self._table_name} WHERE slot >= %s AND slot <= %s AND finalized = false',
                       (from_slot, to_slot))

    def get_tx_by_neon_sign(self, neon_sign) -> NeonTxDBInfo:
        return self._tx_from_value(self._fetchone(self._column_lst, [('neon_sign', neon_sign)]))

    def get_tx_by_sol_sign(self, sol_sign) -> NeonTxDBInfo:
        return self._tx_from_value(self._fetchone(self._column_lst, [('sol_sign', sol_sign)]))
