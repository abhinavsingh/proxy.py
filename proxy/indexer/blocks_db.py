from .utils import BaseDB, str_fmt_object


class SolanaBlockDBInfo:
    def __init__(self, slot=None, finalized=False, height=None, hash=None, parent_hash=None, time=None, signs=None):
        self.slot = slot
        self.finalized = finalized
        self.height = height
        self.hash = hash
        self.parent_hash = parent_hash
        self.time = time
        self.signs = signs

    def __str__(self):
        return str_fmt_object(self)


class SolanaBlocksDB(BaseDB):
    def __init__(self):
        BaseDB.__init__(self)
        self._column_lst = ('slot', 'finalized', 'height', 'hash')
        self._full_column_lst = ('slot', 'finalized', 'height', 'hash', 'parent_hash', 'blocktime', 'signatures')

    def _create_table_sql(self) -> str:
        self._table_name = 'solana_blocks'
        return f"""
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                slot BIGINT,
                finalized BOOLEAN,
                height BIGINT,
                hash CHAR(66),

                parent_hash CHAR(66),
                blocktime BIGINT,
                signatures BYTEA,

                UNIQUE(slot)
            );
            CREATE INDEX IF NOT EXISTS {self._table_name}_hash ON {self._table_name}(hash);
            CREATE INDEX IF NOT EXISTS {self._table_name}_height ON {self._table_name}(height);
            """

    def _block_from_value(self, value, slot=None) -> SolanaBlockDBInfo:
        if not value:
            return SolanaBlockDBInfo(slot=slot)

        return SolanaBlockDBInfo(
            slot=value[0],
            finalized=value[1],
            height=value[2],
            hash=value[3],
        )

    def _full_block_from_value(self, value, slot=None) -> SolanaBlockDBInfo:
        if not value:
            return SolanaBlockDBInfo(slot=slot)

        return SolanaBlockDBInfo(
            slot=value[0],
            finalized=value[1],
            height=value[2],
            hash=value[3],
            parent_hash=value[4],
            time=value[5],
            signs=self.decode_list(value[6])
        )

    def get_block_by_slot(self, block_slot) -> SolanaBlockDBInfo:
        return self._block_from_value(self._fetchone(self._column_lst, [('slot', block_slot)]), block_slot)

    def get_full_block_by_slot(self, block_slot) -> SolanaBlockDBInfo:
        return self._full_block_from_value(self._fetchone(self._full_column_lst, [('slot', block_slot)]), block_slot)

    def get_block_by_hash(self, block_hash) -> SolanaBlockDBInfo:
        return self._block_from_value(self._fetchone(self._column_lst, [('hash', block_hash)]))

    def get_block_by_height(self, block_num) -> SolanaBlockDBInfo:
        return self._block_from_value(self._fetchone(self._column_lst, [('height', block_num)]))

    def set_block(self, block: SolanaBlockDBInfo):
        cursor = self._conn.cursor()
        cursor.execute(f'''
            INSERT INTO {self._table_name}
            ({', '.join(self._full_column_lst)})
            VALUES
            ({', '.join(['%s' for _ in range(len(self._full_column_lst))])})
            ON CONFLICT (slot) DO UPDATE SET
                hash=EXCLUDED.hash,
                height=EXCLUDED.height,
                parent_hash=EXCLUDED.parent_hash,
                blocktime=EXCLUDED.blocktime,
                signatures=EXCLUDED.signatures
            ''',
            (block.slot, block.finalized, block.height, block.hash,
             block.parent_hash, block.time, self.encode_list(block.signs)))

    def fill_block_height(self, height, slots):
        rows = []
        for slot in slots:
            rows.append((slot, height))
            height += 1

        cursor = self._conn.cursor()
        cursor.executemany(
            f'INSERT INTO {self._table_name}(slot, finalized, height) VALUES(%s, True, %s) ON CONFLICT DO NOTHING',
            rows)

    def del_not_finalized(self, from_slot: int, to_slot: int):
        cursor = self._conn.cursor()
        cursor.execute(f'DELETE FROM {self._table_name} WHERE slot >= %s AND slot <= %s AND finalized = false',
                       (from_slot, to_slot))
