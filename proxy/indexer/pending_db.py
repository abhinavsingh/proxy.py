from .utils import BaseDB


class PendingTxError(Exception):
    def __init__(self, err):
        super().__init__(err)


class NeonPendingTxInfo:
    def __init__(self, neon_sign: str, slot: int, operator: str):
        self.neon_sign = neon_sign
        self.slot = slot
        self.operator = operator


class NeonPendingTxsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_pending_transactions'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                neon_sign CHAR(66),
                slot BIGINT,
                operator CHAR(50),

                UNIQUE(neon_sign)
            );
            CREATE INDEX IF NOT EXISTS {self._table_name}_slot ON {self._table_name}(slot);
            """

    def set_tx(self, tx: NeonPendingTxInfo):
        cursor = self._conn.cursor()
        # Update slot only for this Operator:ResourceId
        cursor.execute(f'''
                        INSERT INTO {self._table_name}
                            (neon_sign, slot, operator)
                        VALUES
                            (%s, %s, %s)
                        ON CONFLICT (neon_sign)
                        DO UPDATE SET
                            slot = EXCLUDED.slot
                        WHERE {self._table_name}.operator = EXCLUDED.operator
                       ''',
                       (tx.neon_sign, tx.slot, tx.operator))

        values = self._fetchone(['operator'], [('neon_sign', tx.neon_sign)], ['slot desc'])
        if not values or values[0].strip() != tx.operator.strip():
            raise PendingTxError('Transaction is locked in other worker')

    def del_not_finalized(self, from_slot: int, to_slot: int):
        cursor = self._conn.cursor()
        cursor.execute(f'DELETE FROM {self._table_name} WHERE slot <= %s', [to_slot])

    def get_slot(self, neon_sign: str) -> int:
        values = self._fetchone(['slot'], [('neon_sign', neon_sign)], ['slot desc'])
        if not values:
            return 0
        return int(values[0])
