from .utils import BaseDB


class PendingTxError(Exception):
    def __init__(self, err):
        super().__init__(err)


class NeonPendingTxInfo:
    def __init__(self, neon_sign: str, slot: int, pid: int):
        self.neon_sign = neon_sign
        self.slot = slot
        self.pid = pid


class NeonPendingTxsDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'neon_pending_transactions'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                neon_sign CHAR(66),
                slot BIGINT,
                pid INT,

                UNIQUE(neon_sign)
            );
            CREATE INDEX IF NOT EXISTS {self._table_name}_slot ON {self._table_name}(slot);
            """

    def set_tx(self, tx: NeonPendingTxInfo):
        cursor = self._conn.cursor()
        # Update slot only for this PID
        cursor.execute(f'''
                        INSERT INTO {self._table_name}
                            (neon_sign, slot, pid)
                        VALUES
                            (%s, %s, %s)
                        ON CONFLICT (neon_sign)
                        DO UPDATE SET
                            slot = EXCLUDED.slot
                        WHERE {self._table_name}.pid = EXCLUDED.pid
                       ''',
                       (tx.neon_sign, tx.slot, tx.pid))

        values = self._fetchone(['pid'], [('neon_sign', tx.neon_sign)], ['slot desc'])
        if not values or int(values[0]) != tx.pid:
            raise PendingTxError('Transaction is locked in other worker')

    def del_not_finalized(self, from_slot: int, to_slot: int):
        cursor = self._conn.cursor()
        cursor.execute(f'DELETE FROM {self._table_name} WHERE slot <= %s', [to_slot])

    def get_slot(self, neon_sign: str) -> int:
        values = self._fetchone(['slot'], [('neon_sign', neon_sign)], ['slot desc'])
        if not values:
            return 0
        return int(values[0])
