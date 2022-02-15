from typing import Optional

import base58
import time
from logged_groups import logged_group, logging_context
from solana.rpc.api import Client
from solana.system_program import SYS_PROGRAM_ID

from ..indexer.indexer_base import IndexerBase
from ..indexer.indexer_db import IndexerDB
from ..indexer.utils import SolanaIxSignInfo, MetricsToLogBuff
from ..indexer.utils import get_accounts_from_storage, check_error
from ..indexer.canceller import Canceller

from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, str_fmt_object

from ..environment import EVM_LOADER_ID, FINALIZED, CANCEL_TIMEOUT, SOLANA_URL


@logged_group("neon.Indexer")
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
        self.canceled = False

    def __str__(self):
        return str_fmt_object(self)


@logged_group("neon.Indexer")
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
    def __init__(self, db: IndexerDB, solana_client: Client):
        self._db = db
        self._client = solana_client
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
                with logging_context(neon_tx=tx.neon_tx.sign[:7]):
                    self._db.submit_transaction(tx.neon_tx, tx.neon_res, tx.used_ixs)
            self.del_tx(tx)
        self._done_tx_list.clear()

        holders = len(self._holder_table)
        transactions = len(self._tx_table)
        used_ixs = len(self._used_ixs)
        if holders > 0 or transactions > 0 or used_ixs > 0:
            self.debug('Receipt state stats: ' +
                        f'holders {holders}, ' +
                        f'transactions {transactions}, ' +
                        f'used ixs {used_ixs}')

    def iter_txs(self):
        for tx in self._tx_table.values():
            yield tx

    def add_account_to_db(self, neon_account: str, pda_account: str, code_account: str, slot: int):
        self._db.fill_account_info_by_indexer(neon_account, pda_account, code_account, slot)


@logged_group("neon.Indexer")
class DummyIxDecoder:
    def __init__(self, name: str, state: ReceiptsParserState):
        self.name = name
        self.state = state

    def __str__(self):
        return f'{self.name} {self.state.ix}'

    @staticmethod
    def neon_addr_fmt(neon_tx: NeonTxInfo):
        return f'Neon tx {neon_tx.sign}, Neon addr {neon_tx.addr}'

    def _getadd_tx(self, storage_account, neon_tx=None, blocked_accounts=None) -> NeonTxObject:
        if blocked_accounts is None:
            blocked_accounts = ['']
        tx = self.state.get_tx(storage_account)
        if tx and neon_tx and tx.neon_tx and (neon_tx.sign != tx.neon_tx.sign):
            self.warning(f'tx.neon_tx({tx.neon_tx}) != neon_tx({neon_tx}), storage: {storage_account}')
            self.state.unmark_ix_used(tx)
            self.state.del_tx(tx)
            tx = None

        if not tx:
            tx = self.state.add_tx(storage_account=storage_account)
            tx.blocked_accounts = blocked_accounts
        if neon_tx:
            tx.neon_tx = neon_tx
        return tx

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
        self.debug(f'{msg} - {obj}')
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
        self.debug(f'{msg} - {obj}')
        return True

    def _decoding_skip(self, reason: str) -> bool:
        """Skip decoding of the instruction"""
        self.debug(f'{reason}')
        return False

    def _decoding_fail(self, obj: BaseEvmObject, reason: str) -> bool:
        """
        Assembling of objects has been failed:
        - destroy the intermediate objects;
        - unmark all instructions as unused.

        Show errors in warning mode because it can be a result of restarting.
        """
        self.warning(f'{reason} - {obj}')
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
            tx.neon_res.decode(tx.neon_tx.sign, self.ix.tx, self.ix.sign.idx)
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

        rlp_error = tx.neon_tx.decode(rlp_sign=rlp_sign, rlp_data=bytes(rlp_data)).error
        if rlp_error:
            self.error(f'Neon tx rlp error: {rlp_error}')

        tx.holder_account = holder_account
        tx.move_ix_used(holder)
        self._decoding_done(holder, f'init {self.neon_addr_fmt(tx.neon_tx)} from holder')
        return tx

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        return self._decoding_skip(f'no logic to decode the instruction: {self.state.ix.ix_data.hex()[:8]}')


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


class CreateAccountIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'CreateAccount', state)

    def execute(self) -> bool:
        self._decoding_start()

        if check_error(self.ix.tx):
            return self._decoding_skip("Ignore failed create account")

        if len(self.ix.ix_data) < 41:
            return self._decoding_skip(f'not enough data to get the Neon account {len(self.ix.ix_data)}')

        neon_account = "0x" + self.ix.ix_data[8+8+4:][:20].hex()
        pda_account = self.ix.get_account(1)
        code_account = self.ix.get_account(3)
        if code_account == str(SYS_PROGRAM_ID) or code_account == '':
            code_account = None

        self.debug(f"neon_account({neon_account}), pda_account({pda_account}), code_account({code_account}), slot({self.ix.sign.slot})")

        self.state.add_account_to_db(neon_account, pda_account, code_account, self.ix.sign.slot)
        return True


class ResizeStorageAccountIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ResizeStorageAccount', state)

    def execute(self) -> bool:
        self._decoding_start()

        if check_error(self.ix.tx):
            return self._decoding_skip("Ignore failed resize account")

        pda_account = self.ix.get_account(0)
        code_account = self.ix.get_account(2)

        self.debug(f"pda_account({pda_account}), code_account({code_account}), slot({self.ix.sign.slot})")

        self.state.add_account_to_db(None, pda_account, code_account, self.ix.sign.slot)
        return True


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

        neon_res = NeonTxResultInfo(neon_tx.sign, self.ix.tx, self.ix.sign.idx)
        tx = NeonTxObject('', neon_tx=neon_tx, neon_res=neon_res)
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

        tx.neon_res.canceled(self.ix.tx)
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


@logged_group("neon.Indexer")
class BlocksIndexer:
    def __init__(self, db: IndexerDB, solana_client: Client):
        self.db = db
        self.solana_client = solana_client
        self.counted_logger = MetricsToLogBuff()

    def gather_blocks(self):
        start_time = time.time()
        latest_block = self.db.get_latest_block()
        height = -1
        min_height = height
        confirmed_blocks_len = 10000
        client = self.solana_client._provider
        list_opts = {"commitment": FINALIZED}
        block_opts = {"commitment": FINALIZED, "transactionDetails": "none", "rewards": False}
        while confirmed_blocks_len == 10000:
            confirmed_blocks = client.make_request("getBlocksWithLimit", latest_block.slot, confirmed_blocks_len, list_opts)['result']
            confirmed_blocks_len = len(confirmed_blocks)
            # No more blocks
            if confirmed_blocks_len == 0:
                break

            # Intitialize start height
            if height == -1:
                first_block = client.make_request("getBlock", confirmed_blocks[0], block_opts)
                height = first_block['result']['blockHeight']

            # Validate last block height
            latest_block.height = height + confirmed_blocks_len - 1
            latest_block.slot = confirmed_blocks[confirmed_blocks_len - 1]
            last_block = client.make_request("getBlock", latest_block.slot, block_opts)
            if not last_block['result'] or last_block['result']['blockHeight'] != latest_block.height:
                self.warning(f"FAILED last_block_height {latest_block.height} " +
                             f"last_block_slot {latest_block.slot} " +
                             f"last_block {last_block}")
                break

            # Everything is good
            min_height = min(min_height, height) if min_height > 0 else height
            self.db.fill_block_height(height, confirmed_blocks)
            height = latest_block.height

        gather_blocks_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.counted_logger.print(
            self.debug,
            list_params={"gather_blocks_ms": gather_blocks_ms, "processed_height": latest_block.height - min_height},
            latest_params={"last_block_slot": latest_block.slot}
        )


@logged_group("neon.Indexer")
class Indexer(IndexerBase):
    def __init__(self, solana_url, evm_loader_id):
        self.debug(f'Finalized commitment: {FINALIZED}')
        self.db = IndexerDB()
        last_known_slot = self.db.get_min_receipt_slot()
        IndexerBase.__init__(self, solana_url, evm_loader_id, last_known_slot)
        self.indexed_slot = self.last_slot
        self.db.set_client(self.solana_client)
        self.canceller = Canceller()
        self.blocked_storages = {}
        self._init_last_height_slot()
        self.block_indexer = BlocksIndexer(db=self.db, solana_client=self.solana_client)
        self.counted_logger = MetricsToLogBuff()

        self.state = ReceiptsParserState(db=self.db, solana_client=self.solana_client)
        self.ix_decoder_map = {
            0x00: WriteIxDecoder(self.state),
            0x01: DummyIxDecoder('Finalize', self.state),
            0x02: CreateAccountIxDecoder(self.state),
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
            0x0f: DummyIxDecoder('ERC20CreateTokenAccount', self.state),
            0x11: ResizeStorageAccountIxDecoder(self.state),
            0x12: WriteWithHolderIxDecoder(self.state),
            0x13: PartialCallV02IxDecoder(self.state),
            0x14: ContinueV02IxDecoder(self.state),
            0x15: CancelV02IxDecoder(self.state),
            0x16: ExecuteTrxFromAccountV02IxDecoder(self.state)
        }
        self.def_decoder = DummyIxDecoder('Unknown', self.state)

    def _init_last_height_slot(self):
        last_known_slot = self.db.get_latest_block().slot
        slot = self._init_last_slot('height', last_known_slot)
        if last_known_slot == slot:
            return

        block_opts = {"commitment": FINALIZED, "transactionDetails": "none", "rewards": False}
        client = self.solana_client._provider
        block = client.make_request("getBlock", slot, block_opts)
        if not block['result']:
            self.warning(f"Solana haven't return block information for the slot {slot}")
            return

        height = block['result']['blockHeight']
        self.db.fill_block_height(height, [slot])

    def process_functions(self):
        self.block_indexer.gather_blocks()
        IndexerBase.process_functions(self)
        self.process_receipts()
        self.canceller.unlock_accounts(self.blocked_storages)
        self.blocked_storages = {}

    def process_receipts(self):
        start_time = time.time()

        max_slot = 0
        last_block_slot = self.db.get_latest_block().slot

        for slot, sign, tx in self.transaction_receipts.get_trxs(self.indexed_slot, reverse=False):
            if slot > last_block_slot:
                break

            if max_slot != slot:
                self.state.complete_done_txs()
                max_slot = max(max_slot, slot)

            ix_info = SolanaIxInfo(sign=sign, slot=slot,  tx=tx)

            for _ in ix_info.iter_ixs():
                req_id = ix_info.sign.get_req_id()
                with logging_context(sol_tx=req_id):
                        self.state.set_ix(ix_info)
                        (self.ix_decoder_map.get(ix_info.evm_ix) or self.def_decoder).execute()

        self.indexed_slot = last_block_slot
        self.db.set_min_receipt_slot(self.state.find_min_used_slot(self.indexed_slot))

        # cancel transactions with long inactive time
        for tx in self.state.iter_txs():
            if tx.storage_account and abs(tx.slot - self.current_slot) > CANCEL_TIMEOUT:
                if not self.unlock_accounts(tx):
                    tx.neon_res.slot = self.indexed_slot
                    self.state.done_tx(tx)

        # after last instruction and slot
        self.state.complete_done_txs()

        process_receipts_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.counted_logger.print(
            self.debug,
            list_params={"process_receipts_ms": process_receipts_ms, "processed_slots": self.current_slot - self.indexed_slot},
            latest_params={"transaction_receipts.len": self.transaction_receipts.size(), "indexed_slot": self.indexed_slot}
        )

    def unlock_accounts(self, tx) -> bool:
        # We already indexed the transaction
        if tx.neon_res.is_valid():
            return True

        # We already sent Cancel and waiting for reciept
        if tx.canceled:
            return True

        if not tx.blocked_accounts:
            self.warning(f"Transaction {tx.neon_tx} hasn't blocked accounts.")
            return False

        storage_accounts_list = get_accounts_from_storage(self.solana_client, tx.storage_account)
        if storage_accounts_list is None:
            self.warning(f"Transaction {tx.neon_tx} has empty storage.")
            return False

        if storage_accounts_list != tx.blocked_accounts:
            self.warning(f"Transaction {tx.neon_tx} has another list of accounts than storage.")
            return False

        self.debug(f'Neon tx is blocked: storage {tx.storage_account}, {tx.neon_tx}')
        self.blocked_storages[tx.storage_account] = (tx.neon_tx, tx.blocked_accounts)
        tx.canceled = True
        return True


@logged_group("neon.Indexer")
def run_indexer(solana_url, evm_loader_id, *, logger):
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id}""")

    indexer = Indexer(solana_url, evm_loader_id)
    indexer.run()


if __name__ == "__main__":
    solana_url = SOLANA_URL
    evm_loader_id = EVM_LOADER_ID
    run_indexer(solana_url, evm_loader_id)
