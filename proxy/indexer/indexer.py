from typing import Optional

import base58
import os
import time
from logged_groups import logged_group

try:
    from indexer_base import IndexerBase, PARALLEL_REQUESTS
    from indexer_db import IndexerDB
    from utils import SolanaIxSignInfo, NeonTxResultInfo, NeonTxSignInfo, Canceller, str_fmt_object, FINALIZED
except ImportError:
    from .indexer_base import IndexerBase, PARALLEL_REQUESTS
    from .indexer_db import IndexerDB, FINALIZED
    from .utils import SolanaIxSignInfo, NeonTxResultInfo, NeonTxInfo, Canceller, str_fmt_object, FINALIZED

from ..environment import EVM_LOADER_ID

CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", "60"))
UPDATE_BLOCK_COUNT = PARALLEL_REQUESTS * 16


@logged_group("neon.indexer")
class SolanaIxInfo:
    def __init__(self, sign: str, slot: int, tx: {}):
        self.sign = SolanaIxSignInfo(sign=sign, slot=slot, idx=-1)
        self.tx = tx
        self._is_valid = isinstance(tx, dict)
        self._msg = self.tx['transaction']['message'] if self._is_valid else None
        self._set_defaults()

    def __str__(self):
        return f'{self.sign} {self.evm_ix}'

    def _set_defaults(self):
        self.ix = {}
        self.evm_ix = 0xFF
        self.ix_data = None

    def _decode_ixdata(self) -> bool:
        try:
            self.ix_data = base58.b58decode(self.ix['data'])
            self.evm_ix = int(self.ix_data[0])
            return True
        except Exception as e:
            self.debug(f'{self} fail to get a Neon EVM instruction: {e}')
            self.evm_ix = 0xFF
            self.ix_data = None
        return False

    def clear(self):
        self._set_defaults()

    def iter_ixs(self):
        if not self._is_valid:
            return

        self._set_defaults()
        accounts = self._msg['accountKeys']
        tx_ixs = enumerate(self._msg['instructions'])

        evm_ix_idx = -1
        for ix_idx, self.ix in tx_ixs:
            # Make a new object to keep values in existing
            self.sign = SolanaIxSignInfo(sign=self.sign.sign, slot=self.sign.slot, idx=ix_idx)
            if 'programIdIndex' not in self.ix:
                self.debug(f'{self} error: fail to get program id')
                continue
            if accounts[self.ix['programIdIndex']] != EVM_LOADER_ID:
                continue
            if not self._decode_ixdata():
                continue

            evm_ix_idx += 1
            yield evm_ix_idx

        self._set_defaults()

    def get_account_cnt(self):
        assert self._is_valid

        return len(self.ix['accounts'])

    def get_account(self, idx: int) -> str:
        assert self._is_valid

        msg_keys = self._msg['accountKeys']
        ix_accounts = self.ix['accounts']
        if len(ix_accounts) > idx:
            return msg_keys[ix_accounts[idx]]
        return ''

    def get_account_list(self, start: int) -> [str]:
        assert self._is_valid

        msg_keys = self._msg['accountKeys']
        ix_accounts = self.ix['accounts']
        return [msg_keys[idx] for idx in ix_accounts[start:]]


class BaseEvmObject:
    def __init__(self):
        self.used_ixs = []
        self.slot = 0

    def mark_ix_used(self, ix_info: SolanaIxInfo):
        self.used_ixs.append(ix_info.sign)
        self.slot = max(self.slot, ix_info.sign.slot)

    def move_ix_used(self, obj):
        self.used_ixs += obj.used_ixs
        obj.used_ixs.clear()
        self.slot = max(self.slot, obj.slot)


class NeonHolderObject(BaseEvmObject):
    def __init__(self, account: str):
        BaseEvmObject.__init__(self)
        self.account = account
        self.data = bytes()
        self.count_written = 0
        self.max_written = 0

    def __str__(self):
        return str_fmt_object(self)


class NeonTxObject(BaseEvmObject):
    def __init__(self, storage_account: str, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo):
        BaseEvmObject.__init__(self)
        self.storage_account = storage_account
        self.neon_tx = (neon_tx or NeonTxInfo())
        self.neon_res = (neon_res or NeonTxResultInfo())
        self.step_count = []
        self.holder_account = ''
        self.blocked_accounts = []

    def __str__(self):
        return str_fmt_object(self)


@logged_group("neon.indexer")
class ReceiptsParserState:
    """
    Each instruction is passed to a decoder (see DummyIxDecoder bellow).

    The decoder analyzes the instruction and stores the intermediate data in the parser state:
    - _holder_table contains Neon holder accounts for big Neon transactions;
    - _tx_table contains Neon transactions.

    Holder accounts are required to execute big Neon transactions.
    The execution of a big Neon transaction contains two steps:
    - storing chunks of the Neon transaction into the holder account;
    - executing of the Neon transaction by passing the holder account to the Neon EVM program.

    On parsing the instruction is stored into the intermediate object (holder, transaction) and in the _used_ixs.
    If an error occurs while decoding, the decoder can skip this instruction.

    So, in the _used_ixs the parser stores all instructions needed for assembling intermediate objects. After
    each cycle the parser stores the number of the smallest slot from the _used_ixs. That is why, the parser can be
    restarted in any moment.

    After restarting the parser:
    - Restores the intermediate state of objects;
    - And continues the decoding process.

    When the whole Neon transaction is assembled:
    - Neon transaction is stored into the DB;
    - All instructions used for assembly the transaction are stored into the DB;
    - All instructions are removed from the _used_ixs;
    - If number of the smallest slot in the _used_ixs is changed, it's stored into the DB for the future restart.
    """
    def __init__(self, db: IndexerDB, client):
        self._db = db
        self._client = client
        self._holder_table = {}
        self._tx_table = {}
        self._done_tx_list = []
        self._used_ixs = {}
        self.ix = SolanaIxInfo(sign='', slot=-1, tx=None)

    def set_ix(self, ix_info: SolanaIxInfo):
        self.ix = ix_info

    def mark_ix_used(self, obj: BaseEvmObject):
        self._used_ixs.setdefault(self.ix.sign, 0)
        self._used_ixs[self.ix.sign] += 1

        obj.mark_ix_used(self.ix)

    def unmark_ix_used(self, obj: BaseEvmObject):
        for ix in obj.used_ixs:
            self._used_ixs[ix] -= 1
            if self._used_ixs[ix] == 0:
                del self._used_ixs[ix]

    def find_min_used_slot(self, min_slot):
        for ix in self._used_ixs:
            min_slot = min(min_slot, ix.slot)
        return min_slot

    def get_holder(self, account: str) -> Optional[NeonHolderObject]:
        return self._holder_table.get(account)

    def add_holder(self, account: str) -> NeonHolderObject:
        if account in self._holder_table:
            self.debug(f'{self.ix} ATTENTION: the holder {account} is already used!')

        holder = NeonHolderObject(account=account)
        self._holder_table[account] = holder
        return holder

    def del_holder(self, holder: NeonHolderObject):
        self._holder_table.pop(holder.account, None)

    def get_tx(self, storage_account: str) -> Optional[NeonTxObject]:
        return self._tx_table.get(storage_account)

    def add_tx(self, storage_account: str, neon_tx=None, neon_res=None) -> NeonTxObject:
        if storage_account in self._tx_table:
            self.debug(f'{self.ix} ATTENTION: the tx {storage_account} is already used!')

        tx = NeonTxObject(storage_account=storage_account, neon_tx=neon_tx, neon_res=neon_res)
        self._tx_table[storage_account] = tx
        return tx

    def del_tx(self, tx: NeonTxObject):
        self._tx_table.pop(tx.storage_account, None)

    def done_tx(self, tx: NeonTxObject):
        """
        Continue waiting of ixs in the slot with the same neon tx,
        because the parsing order can be other than the execution order.
        """
        self._done_tx_list.append(tx)

    def complete_done_txs(self):
        """
        Slot is done, store all done neon txs into the DB.
        """
        for tx in self._done_tx_list:
            self.unmark_ix_used(tx)
            if tx.neon_tx.is_valid() and tx.neon_res.is_valid():
                self._db.submit_transaction(tx.neon_tx, tx.neon_res, tx.used_ixs, commitment=FINALIZED)
            self.del_tx(tx)
        self._done_tx_list.clear()

    def iter_txs(self) -> NeonTxObject:
        for tx in self._tx_table.values():
            yield tx


@logged_group("neon.indexer")
class DummyIxDecoder:
    def __init__(self, name: str, state: ReceiptsParserState):
        self.name = name
        self.state = state

    def __str__(self):
        return f'{self.name} {self.state.ix}'

    @staticmethod
    def neon_addr_fmt(neon_tx: NeonTxInfo):
        return f'Neon tx {neon_tx.sign}, Neon addr {neon_tx.addr}'

    def _getadd_tx(self, storage_account, neon_tx=None, blocked_accounts=[str]) -> NeonTxObject:
        tx = self.state.get_tx(storage_account)
        if tx and neon_tx and tx.neon_tx and (neon_tx.sign != tx.neon_tx.sign):
            self._log_warning(f'storage {storage_account}, tx.neon_tx({tx.neon_tx}) != neon_tx({neon_tx})')
            self.state.unmark_ix_used(tx)
            self.state.del_tx(tx)
            tx = None

        if not tx:
            tx = self.state.add_tx(storage_account=storage_account)
            tx.blocked_accounts = blocked_accounts
        if neon_tx:
            tx.neon_tx = neon_tx
        return tx

    def _log_warning(self, msg: str):
        self.warning(f'{self}: {msg}')

    def _decoding_start(self):
        """
        Start decoding process:
        - get the instruction from the parser state;
        - log the start of decoding.
        """
        self.ix = self.state.ix
        self.debug(f'{self} ...')

    def _decoding_success(self, obj: BaseEvmObject, msg: str) -> bool:
        """
        The instruction has been successfully parsed:
        - Mark the instruction as used;
        - log the success message.
        """
        self.state.mark_ix_used(obj)
        self.debug(f'{self}: {msg} - {obj}')
        return True

    def _decoding_done(self, obj: BaseEvmObject, msg: str) -> bool:
        """
        Assembling of the object has been successfully finished.
        """
        if isinstance(obj, NeonTxObject):
            self.state.mark_ix_used(obj)
            self.state.done_tx(obj)
        elif isinstance(obj, NeonHolderObject):
            self.state.unmark_ix_used(obj)
            self.state.del_holder(obj)
        else:
            assert False, 'Unknown type of object'
        self.debug(f'{self}: {msg} - {obj}')
        return True

    def _decoding_skip(self, reason: str) -> bool:
        """Skip decoding of the instruction"""
        self.error(f'{self}: {reason}')
        return False

    def _decoding_fail(self, obj: BaseEvmObject, reason: str) -> bool:
        """
        Assembling of objects has been failed:
        - destroy the intermediate objects;
        - unmark all instructions as unused.

        Show errors in warning mode because it can be a result of restarting.
        """
        self.warning(f'{self}: {reason} - {obj}')
        self.state.unmark_ix_used(obj)

        if isinstance(obj, NeonTxObject):
            self.state.del_tx(obj)
        elif isinstance(obj, NeonHolderObject):
            self.state.del_holder(obj)
        else:
            assert False, 'Unknown type of object'
        return False

    def _decode_tx(self, tx: NeonTxObject):
        """
        If the transaction doesn't have results, then try to get results for the transaction.
        If the transaction has received results, then call done for the transaction.
        The transaction can already have results, because parser waits all ixs in the slot, because
        the parsing order can be other than the execution order
        """
        if not tx.neon_res.is_valid():
            tx.neon_res.decode(self.ix.tx, self.ix.sign.idx)
            if tx.neon_res.is_valid():
                return self._decoding_done(tx, 'found Neon results')
        return self._decoding_success(tx, 'mark ix used')

    def _init_tx_from_holder(self, holder_account: str, storage_account: str, blocked_accounts: [str]) -> Optional[NeonTxObject]:
        tx = self._getadd_tx(storage_account, blocked_accounts=blocked_accounts)
        if tx.holder_account:
            return tx

        holder = self.state.get_holder(holder_account)
        if not holder:
            self._decoding_skip(f'no holder account {holder_account}')
            return None

        rlp_sign = holder.data[0:65]
        rlp_len = int.from_bytes(holder.data[65:73], "little")
        rlp_endpos = 73 + rlp_len
        rlp_data = holder.data[73:rlp_endpos]

        rlp_error = tx.neon_tx.decode(rlp_sign=rlp_sign, rlp_data=bytes(rlp_data))
        if rlp_error:
            self._log_warning(f'Neon tx rlp error "{rlp_error}"')

        tx.holder_account = holder_account
        tx.move_ix_used(holder)
        self._decoding_done(holder, f'init {self.neon_addr_fmt(tx.neon_tx)} from holder')
        return tx

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        return self._decoding_skip('no logic to decode the instruction')


class WriteIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'Write', state)

    class _DataChunk:
        def __init__(self, offset=0, length=0, data=bytes()):
            self.offset = offset
            self.length = length
            self.endpos = self.offset + self.length
            self.data = data

        def __str__(self):
            return str_fmt_object(self)

        def is_valid(self) -> bool:
            return (self.length > 0) and (len(self.data) == self.length)

    def _decode_datachunck(self, ix_info: SolanaIxInfo) -> _DataChunk:
        # No enough bytes to get length of chunk
        if len(ix_info.ix_data) < 17:
            return self._DataChunk()

        return self._DataChunk(
            offset=int.from_bytes(ix_info.ix_data[4:8], "little"),
            length=int.from_bytes(ix_info.ix_data[8:16], "little"),
            data=ix_info.ix_data[16:],
        )

    def execute(self) -> bool:
        self._decoding_start()

        chunk = self._decode_datachunck(self.ix)
        if not chunk.is_valid():
            return self._decoding_skip(f'bad data chunk {chunk}')
        if self.ix.get_account_cnt() < 1:
            return self._decoding_skip(f'no enough accounts {self.ix.get_account_cnt()}')

        holder_account = self.ix.get_account(0)
        holder = self.state.get_holder(holder_account)
        if not holder:
            holder = self.state.add_holder(holder_account)

        # Write the received chunk into the holder account buffer
        holder.max_written = max(holder.max_written, chunk.endpos)
        if len(holder.data) < holder.max_written:
            holder.data += bytes(holder.max_written - len(holder.data))
        holder.data = holder.data[:chunk.offset] + chunk.data + holder.data[chunk.endpos:]
        holder.count_written += chunk.length

        return self._decoding_success(holder, f'add chunk {chunk}')


class WriteWithHolderIxDecoder(WriteIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'WriteWithHolder', state)

    def _decode_datachunck(self, ix_info: SolanaIxInfo) -> WriteIxDecoder._DataChunk:
        # No enough bytes to get length of chunk
        if len(ix_info.ix_data) < 22:
            return self._DataChunk()

        return self._DataChunk(
            offset=int.from_bytes(ix_info.ix_data[9:13], "little"),
            length=int.from_bytes(ix_info.ix_data[13:21], "little"),
            data=ix_info.ix_data[21:]
        )


class CallFromRawIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'CallFromRaw', state)

    def execute(self) -> bool:
        self._decoding_start()

        if len(self.ix.ix_data) < 92:
            return self._decoding_skip('no enough data to get the Neon tx')

        rlp_sign = self.ix.ix_data[25:90]
        rlp_data = self.ix.ix_data[90:]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        tx = NeonTxObject('', neon_tx=neon_tx, neon_res=NeonTxResultInfo(self.ix.tx, self.ix.sign.idx))
        return self._decoding_done(tx, 'call success')


class PartialCallIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallFromRawEthereumTX', state)

    def execute(self) -> bool:
        self._decoding_start()

        blocked_accounts_start = 7

        if self.ix.get_account_cnt() < blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')
        if len(self.ix.ix_data) < 100:
            return self._decoding_skip('no enough data to get arguments')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(blocked_accounts_start)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')
        rlp_sign = self.ix.ix_data[33:98]
        rlp_data = self.ix.ix_data[98:]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        tx = self._getadd_tx(storage_account, neon_tx=neon_tx, blocked_accounts=blocked_accounts)
        tx.step_count.append(step_count)
        return self._decode_tx(tx)


class PartialCallV02IxDecoder(PartialCallIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallFromRawEthereumTXv02', state)


class PartialCallOrContinueIxDecoder(PartialCallIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallOrContinueFromRawEthereumTX', state)


class ContinueIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'Continue', state)
        self._blocked_accounts_start = 5

    def execute(self) -> bool:
        self._decoding_start()

        if self.ix.get_account_cnt() < self._blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')
        if len(self.ix.ix_data) < 14:
            return self._decoding_skip('no enough data to get arguments')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(self._blocked_accounts_start)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')

        tx = self._getadd_tx(storage_account, blocked_accounts=blocked_accounts)
        tx.step_count.append(step_count)
        return self._decode_tx(tx)


class ContinueV02IxDecoder(ContinueIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ContinueV02', state)
        self._blocked_accounts_start = 6


class ExecuteTrxFromAccountIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterative', state)
        self._blocked_accounts_start = 5

    def execute(self) -> bool:
        self._decoding_start()

        if self.ix.get_account_cnt() < self._blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')

        holder_account = self.ix.get_account(0)
        storage_account = self.ix.get_account(1)
        blocked_accounts = self.ix.get_account_list(self._blocked_accounts_start)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')

        tx = self._init_tx_from_holder(holder_account, storage_account, blocked_accounts)
        if not tx:
            return self._decoding_skip(f'fail to init in storage {storage_account} from holder {holder_account}')
        tx.step_count.append(step_count)
        return self._decode_tx(tx)


class ExecuteTrxFromAccountV02IxDecoder(ExecuteTrxFromAccountIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterativeV02', state)
        self._blocked_accounts_start = 7


class CancelIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'Cancel', state)

    def execute(self) -> bool:
        self._decoding_start()

        blocked_accounts_start = 6
        if self.ix.get_account_cnt() < blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(blocked_accounts_start)

        tx = self._getadd_tx(storage_account, blocked_accounts=blocked_accounts)
        if not tx.neon_tx.is_valid():
            return self._decoding_fail(tx, f'cannot find storage {tx}')

        tx.neon_res.clear()
        tx.neon_res.slot = self.ix.sign.slot
        return self._decoding_done(tx, f'cancel success')


class CancelV02IxDecoder(CancelIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'CancelV02', state)


class ExecuteOrContinueIxParser(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterativeOrContinue', state)

    def execute(self) -> bool:
        self._decoding_start()
        blocked_accounts_start = 7

        if self.ix.get_account_cnt() < blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')

        holder_account = self.ix.get_account(0)
        storage_account = self.ix.get_account(1)
        blocked_accounts = self.ix.get_account_list(blocked_accounts_start)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')

        tx = self._init_tx_from_holder(holder_account, storage_account, blocked_accounts)
        if not tx:
            return self._decoding_skip(f'fail to init the storage {storage_account} from the holder {holder_account}')
        tx.step_count.append(step_count)
        return self._decode_tx(tx)


@logged_group("neon.indexer")
class Indexer(IndexerBase):
    def __init__(self, solana_url, evm_loader_id):
        IndexerBase.__init__(self, solana_url, evm_loader_id, 0)
        self.db = IndexerDB(self.client)
        self.canceller = Canceller()
        self.blocked_storages = {}
        self.processed_slot = self.db.get_min_receipt_slot()
        self.debug(f'Minimum receipt slot: {self.processed_slot}')
        self.debug(f'Finalized commitment: {FINALIZED}')

        self.state = ReceiptsParserState(db=self.db, client=self.client)
        self.ix_decoder_map = {
            0x00: WriteIxDecoder(self.state),
            0x01: DummyIxDecoder('Finalize', self.state),
            0x02: DummyIxDecoder('CreateAccount', self.state),
            0x03: DummyIxDecoder('Call', self.state),
            0x04: DummyIxDecoder('CreateAccountWithSeed', self.state),
            0x05: CallFromRawIxDecoder(self.state),
            0x06: DummyIxDecoder('OnEvent', self.state),
            0x07: DummyIxDecoder('OnResult', self.state),
            0x09: PartialCallIxDecoder(self.state),
            0x0a: ContinueIxDecoder(self.state),
            0x0b: ExecuteTrxFromAccountIxDecoder(self.state),
            0x0c: CancelIxDecoder(self.state),
            0x0d: PartialCallOrContinueIxDecoder(self.state),
            0x0e: ExecuteOrContinueIxParser(self.state),
            0x12: WriteWithHolderIxDecoder(self.state),
            0x13: PartialCallV02IxDecoder(self.state),
            0x14: ContinueV02IxDecoder(self.state),
            0x15: CancelV02IxDecoder(self.state),
            0x16: ExecuteTrxFromAccountV02IxDecoder(self.state)
        }
        self.def_decoder = DummyIxDecoder('Unknown', self.state)

    def process_functions(self):
        IndexerBase.process_functions(self)
        self.debug("Start getting blocks")
        (start_block_slot, last_block_slot) = self.gather_blocks()
        self.debug("Process receipts")
        self.process_receipts()
        self.debug(f'remove not finalized data in range[{start_block_slot}..{last_block_slot}]')
        self.db.del_not_finalized(from_slot=start_block_slot, to_slot=last_block_slot)
        self.debug("Unlock accounts")
        self.canceller.unlock_accounts(self.blocked_storages)
        self.blocked_storages = {}

    def process_receipts(self):
        start_time = time.time()

        max_slot = self.processed_slot - 1
        last_block_slot = self.db.get_last_block_slot()

        for slot, sign, tx in self.transaction_receipts.get_trxs(self.processed_slot, reverse=False):
            if slot > last_block_slot:
                break

            if max_slot != slot:
                self.state.complete_done_txs()
                max_slot = max(max_slot, slot)

            ix_info = SolanaIxInfo(sign=sign, slot=slot,  tx=tx)

            for _ in ix_info.iter_ixs():
                self.state.set_ix(ix_info)
                (self.ix_decoder_map.get(ix_info.evm_ix) or self.def_decoder).execute()

        # after last instruction and slot
        self.state.complete_done_txs()

        for tx in self.state.iter_txs():
            if tx.storage_account and abs(tx.slot - self.current_slot) > CANCEL_TIMEOUT:
                self.debug(f'Neon tx is blocked: storage {tx.storage_account}, {tx.neon_tx}')
                self.blocked_storages[tx.storage_account] = (tx.neon_tx, tx.blocked_accounts)

        self.processed_slot = max(self.processed_slot, max_slot + 1)
        self.db.set_min_receipt_slot(self.state.find_min_used_slot(self.processed_slot))

        process_receipts_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.debug(f"process_receipts_ms: {process_receipts_ms} transaction_receipts.len: {self.transaction_receipts.size()} from {self.processed_slot} to {self.current_slot} slots")

    def gather_blocks(self):
        start_time = time.time()
        last_block_slot = self.db.get_last_block_slot()
        max_height = self.db.get_last_block_height()
        start_block_slot = last_block_slot
        height = -1
        confirmed_blocks_len = 10000
        client = self.client._provider
        list_opts = {"commitment": FINALIZED}
        block_opts = {"commitment": FINALIZED, "transactionDetails": "none", "rewards": False}
        while confirmed_blocks_len == 10000:
            confirmed_blocks = client.make_request("getBlocksWithLimit", last_block_slot, confirmed_blocks_len, list_opts)['result']
            confirmed_blocks_len = len(confirmed_blocks)
            # No more blocks
            if confirmed_blocks_len == 0:
                break

            # Intitialize start height
            if height == -1:
                first_block = client.make_request("getBlock", confirmed_blocks[0], block_opts)
                height = first_block['result']['blockHeight']

            # Validate last block height
            max_height = height + confirmed_blocks_len - 1
            last_block_slot = confirmed_blocks[confirmed_blocks_len - 1]
            last_block = client.make_request("getBlock", last_block_slot, block_opts)
            if not last_block['result'] or last_block['result']['blockHeight'] != max_height:
                self.warning(f"FAILED max_height {max_height} last_block_slot {last_block_slot} {last_block}")
                break

            # Everything is good
            self.debug(f"gather_blocks from {height} to {max_height}")
            self.db.fill_block_height(height, confirmed_blocks)
            self.db.set_last_slot_height(last_block_slot, max_height)
            height = max_height

        gather_blocks_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.debug(f"gather_blocks_ms: {gather_blocks_ms} last_height: {max_height} last_block_slot {last_block_slot}")
        return start_block_slot, last_block_slot


@logged_group("neon.indexer")
def run_indexer(solana_url, evm_loader_id, *, logger):
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id}""")

    indexer = Indexer(solana_url, evm_loader_id)
    indexer.run()


if __name__ == "__main__":
    solana_url = os.environ.get('SOLANA_URL', 'http://localhost:8899')
    evm_loader_id = os.environ.get('EVM_LOADER_ID', '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io')
    run_indexer(solana_url, evm_loader_id)
