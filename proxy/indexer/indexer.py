from typing import Iterator, List, Optional, Dict
import time
from enum import Enum

import base58
import sha3
from logged_groups import logged_group, logging_context
from solana.system_program import SYS_PROGRAM_ID

from ..common_neon.data import NeonTxStatData
from ..indexer.i_inidexer_user import IIndexerUser
from ..indexer.accounts_db import NeonAccountInfo
from ..indexer.indexer_base import IndexerBase
from ..indexer.indexer_db import IndexerDB
from ..indexer.utils import SolanaIxSignInfo, MetricsToLogBuff, CostInfo

from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo, str_fmt_object
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_receipt_parser import SolReceiptParser
from ..common_neon.cancel_transaction_executor import CancelTxExecutor
from ..common_neon.evm_decoder import decode_neon_tx_result
from ..common_neon.environment_utils import get_solana_accounts
from ..common_neon.environment_data import EVM_LOADER_ID, FINALIZED, CANCEL_TIMEOUT, SKIP_CANCEL_TIMEOUT, HOLDER_TIMEOUT


@logged_group("neon.Indexer")
class SolanaIxInfo:
    def __init__(self, sign: str, slot: int, tx: Dict):
        self.sign = SolanaIxSignInfo(sign=sign, slot=slot, idx=-1)
        self.cost_info = CostInfo(sign, tx, EVM_LOADER_ID)
        self.tx = tx
        self._is_valid = isinstance(tx, dict)
        self._msg = self.tx['transaction']['message'] if self._is_valid else None
        self._meta = self.tx['meta'] if self._is_valid else None
        self._set_defaults()

    def __str__(self):
        return f'{self.sign} {self.evm_ix}'

    def _set_defaults(self):
        self.ix = {}
        self.neon_obj = None
        self.evm_ix = 0xFF
        self.evm_ix_idx = -1
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

    def _get_neon_instruction(self) -> bool:
        accounts = self._msg['accountKeys']
        if 'programIdIndex' not in self.ix:
            self.debug(f'{self} error: fail to get program id')
            return False
        if accounts[self.ix['programIdIndex']] != EVM_LOADER_ID:
            return False
        if not self._decode_ixdata():
            return False
        return True

    def clear(self):
        self._set_defaults()

    def iter_ixs(self):
        if not self._is_valid:
            return

        self._set_defaults()
        tx_ixs = enumerate(self._msg['instructions'])

        evm_ix_idx = -1
        for ix_idx, self.ix in tx_ixs:
            # Make a new object to keep values in existing
            self.sign = SolanaIxSignInfo(sign=self.sign.sign, slot=self.sign.slot, idx=ix_idx)

            if self._get_neon_instruction():
                evm_ix_idx += 1
                self.evm_ix_idx = evm_ix_idx
                yield self.evm_ix_idx

            for inner_tx in self._meta['innerInstructions']:
                if inner_tx['index'] == ix_idx:
                    for self.ix in inner_tx['instructions']:
                        if self._get_neon_instruction():
                            evm_ix_idx += 1
                            self.evm_ix_idx = evm_ix_idx
                            yield self.evm_ix_idx

        self._set_defaults()

    def get_account_cnt(self):
        assert self._is_valid

        return len(self.ix['accounts'])

    def get_account(self, idx: int) -> str:
        assert self._is_valid

        all_keys = self._get_msg_account_key_list()
        ix_accounts = self.ix['accounts']
        if len(ix_accounts) > idx:
            return all_keys[ix_accounts[idx]]
        return ''

    def _get_msg_account_key_list(self) -> List[str]:
        assert self._is_valid

        all_keys = self._msg['accountKeys']
        lookup_keys = self._meta.get('loadedAddresses', None)
        if lookup_keys is not None:
            all_keys += lookup_keys['writable'] + lookup_keys['readonly']
        return all_keys

    def get_account_list(self, start: int) -> List[str]:
        assert self._is_valid

        all_keys = self._get_msg_account_key_list()
        ix_accounts = self.ix['accounts']
        return [all_keys[idx] for idx in ix_accounts[start:]]


class BaseEvmObject:
    def __init__(self):
        self.used_ixs = []
        self.ixs_cost = []
        self.slot = 0

    def mark_ix_used(self, ix_info: SolanaIxInfo):
        self.used_ixs.append(ix_info.sign)
        self.ixs_cost.append(ix_info.cost_info)
        self.slot = max(self.slot, ix_info.sign.slot)

    def move_ix_used(self, obj):
        self.used_ixs += obj.used_ixs
        self.ixs_cost += obj.ixs_cost
        obj.used_ixs.clear()
        obj.ixs_cost.clear()
        self.slot = max(self.slot, obj.slot)


class NeonHolderObject(BaseEvmObject):
    def __init__(self, account: str):
        BaseEvmObject.__init__(self)
        self.account = account
        self.data = bytes()
        self.count_written = 0
        self.max_written = 0

    def __str__(self) -> str:
        return str_fmt_object(self)


class NeonTxIndexingStatus(Enum):
    IN_PROGRESS = 1
    DONE = 2
    COMPLETED = 3


class NeonTxResult(BaseEvmObject):
    def __init__(self, key: str):
        BaseEvmObject.__init__(self)
        self.key = key
        self.neon_tx = NeonTxInfo()
        self.neon_res = NeonTxResultInfo()
        self.storage_account = ''
        self.holder_account = ''
        self.blocked_accounts = []
        self.canceled = False
        self.status = NeonTxIndexingStatus.IN_PROGRESS

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

    def __init__(self, db: IndexerDB, solana: SolanaInteractor, indexer_user: IIndexerUser):
        self._db = db
        self._solana = solana
        self._user = indexer_user
        self._holder_table = {}
        self._tx_table = {}
        self._done_tx_list = []
        self._used_ixs = {}
        self._tx_costs = []
        self._min_used_slot = 0
        self.ix = SolanaIxInfo(sign='', slot=-1, tx=None)
        self._counted_logger = MetricsToLogBuff()

    def set_ix(self, ix_info: SolanaIxInfo):
        self.ix = ix_info

    def mark_ix_used(self, obj: BaseEvmObject):
        self._used_ixs.setdefault(self.ix.sign, 0)
        self._used_ixs[self.ix.sign] += 1

        obj.mark_ix_used(self.ix)

    def unmark_ix_used(self, obj: BaseEvmObject):
        for ix in obj.used_ixs:
            if ix not in self._used_ixs:
                self.error(f'{ix} is absent in the used ix list')
            self._used_ixs[ix] -= 1
            if self._used_ixs[ix] == 0:
                del self._used_ixs[ix]

    def add_tx_cost(self, cost: CostInfo):
        self._tx_costs.append(cost)

    def find_min_used_slot(self, min_slot) -> int:
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

    def get_tx(self, key: str) -> Optional[NeonTxResult]:
        return self._tx_table.get(key)

    def add_tx(self, key: str) -> NeonTxResult:
        if key in self._tx_table:
            self.debug(f'{self.ix} ATTENTION: the tx {key} is already used!')

        tx = NeonTxResult(key)
        self._tx_table[key] = tx
        return tx

    def del_tx(self, tx: NeonTxResult):
        tx.status = NeonTxIndexingStatus.COMPLETED
        self._tx_table.pop(tx.key, None)

    def done_tx(self, tx: NeonTxResult):
        """
        Continue waiting of ixs in the slot with the same neon tx,
        because the parsing order can be other than the execution order.
        """
        if tx.status != NeonTxIndexingStatus.IN_PROGRESS:
            return
        tx.status = NeonTxIndexingStatus.DONE
        self._done_tx_list.append(tx)

    def _remove_old_holders(self, indexed_slot: int):
        """
        Remove old holders with a long inactive time
        """
        done_holder_list = []
        for holder in self._holder_table.values():
            if abs(holder.slot - indexed_slot) > HOLDER_TIMEOUT:
                done_holder_list.append(holder)

        for holder in done_holder_list:
            self.debug(f'{holder}')
            self.unmark_ix_used(holder)
            self.del_holder(holder)

    def _complete_done_txs(self):
        for tx in self._done_tx_list:
            if tx.status != NeonTxIndexingStatus.DONE:
                continue
            self.debug(f'{tx}')
            self.unmark_ix_used(tx)
            if tx.neon_tx.is_valid() and tx.neon_res.is_valid():
                with logging_context(neon_tx=tx.neon_tx.sign[:7]):
                    self._db.submit_transaction(tx.neon_tx, tx.neon_res, tx.used_ixs)
                    self._complete_neon_tx_result(tx)
            self.del_tx(tx)
        self._done_tx_list.clear()

    def _complete_neon_tx_result(self, tx):
        neon_tx_hash = tx.neon_tx.sign
        neon_income = int(tx.neon_res.gas_used, 0) * int(tx.neon_tx.gas_price, 0)
        if tx.holder_account != '':
            tx_type = 'holder'
        elif tx.storage_account != '':
            tx_type = 'iterative'
        else:
            tx_type = 'single'
        is_canceled = tx.neon_res.status == '0x0'
        neon_tx_stat_data = NeonTxStatData(neon_tx_hash, neon_income, tx_type, is_canceled)
        for sign_info, cost_info in zip(tx.used_ixs, tx.ixs_cost):
            sol_tx_hash = sign_info.sign
            sol_spent = cost_info.sol_spent
            steps = sign_info.steps
            bpf = cost_info.bpf
            neon_tx_stat_data.add_instruction(sol_tx_hash, sol_spent, steps, bpf)

        self._user.on_neon_tx_result(neon_tx_stat_data)

    def _complete_tx_costs(self):
        self._db.add_tx_costs(self._tx_costs)
        self._tx_costs.clear()

    def complete_done_objects(self, indexed_slot: int) -> int:
        """
        Slot is done, store all done neon txs into the DB.
        """
        self._remove_old_holders(indexed_slot)
        self._complete_done_txs()
        self._complete_tx_costs()

        self._min_used_slot = self.find_min_used_slot(indexed_slot)
        self._db.set_min_receipt_slot(self._min_used_slot)

        holders = len(self._holder_table)
        transactions = len(self._tx_table)
        used_ixs = len(self._used_ixs)
        if (holders > 0) or (transactions > 0) or (used_ixs > 0):
            self._counted_logger.print(
                self.debug,
                list_params={},
                latest_params={
                    "holders": holders,
                    "transactions": transactions,
                    "used ixs": used_ixs,
                    "min used slot": self._min_used_slot,
                }
            )
        return self._min_used_slot

    def iter_txs(self) -> Iterator[NeonTxResult]:
        for tx in self._tx_table.values():
            yield tx

    def add_account_to_db(self, neon_account: NeonAccountInfo):
        self._db.fill_account_info_by_indexer(neon_account)


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

    def _getadd_tx(self, storage_account: str,
                   blocked_accounts: List[str],
                   neon_tx: Optional[NeonTxInfo] = None) -> Optional[NeonTxResult]:
        key_data = ';'.join([storage_account] + blocked_accounts)
        key = sha3.sha3_512(key_data.encode('utf-8')).digest().hex()
        tx = self.state.get_tx(key)
        if tx and neon_tx and tx.neon_tx and (neon_tx.sign != tx.neon_tx.sign):
            self.warning(f'tx.neon_tx({tx.neon_tx}) != neon_tx({neon_tx}), storage: {storage_account}')
            self.state.unmark_ix_used(tx)
            self.state.del_tx(tx)
            tx = None

        if tx:
            return tx
        elif not neon_tx:
            return None

        tx = self.state.add_tx(key)
        tx.storage_account = storage_account
        tx.neon_tx = neon_tx
        tx.blocked_accounts = blocked_accounts
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
        if isinstance(obj, NeonTxResult):
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

        if isinstance(obj, NeonTxResult):
            self.state.del_tx(obj)
        elif isinstance(obj, NeonHolderObject):
            self.state.del_holder(obj)
        else:
            assert False, 'Unknown type of object'
        return False

    def _decode_tx(self, tx: NeonTxResult):
        """
        If the transaction doesn't have results, then try to get results for the transaction.
        If the transaction has received results, then call done for the transaction.
        The transaction can already have results, because parser waits all ixs in the slot, because
        the parsing order can be other than the execution order.
        """
        self.ix.neon_obj = tx
        return self._decoding_success(tx, 'mark ix used')

    def _init_tx_from_holder(self,
                             holder_account: str,
                             storage_account: str,
                             blocked_accounts: List[str]) -> Optional[NeonTxResult]:
        tx = self._getadd_tx(storage_account, blocked_accounts)
        if tx:
            return tx

        holder = self.state.get_holder(holder_account)
        if not holder:
            self._decoding_skip(f'no holder account {holder_account}')
            return None

        rlp_sign = holder.data[0:65]
        rlp_len = int.from_bytes(holder.data[65:73], "little")
        rlp_endpos = 73 + rlp_len
        rlp_data = holder.data[73:rlp_endpos]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=bytes(rlp_data))
        if neon_tx.error:
            self.error(f'Neon tx rlp error: {neon_tx.error}')
            return None

        tx = self._getadd_tx(storage_account, blocked_accounts, neon_tx)
        tx.holder_account = holder_account
        tx.move_ix_used(holder)
        self._decoding_done(holder, f'init {tx.neon_tx} from holder')
        return tx

    def execute(self) -> bool:
        """By default, skip the instruction without parsing."""
        return self._decoding_skip(f'no logic to decode the instruction {self.name}({self.state.ix.ix_data.hex()[:8]})')


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

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

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

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip("Ignore failed create account")

        if len(self.ix.ix_data) < 41:
            return self._decoding_skip(f'not enough data to get the Neon account {len(self.ix.ix_data)}')

        neon_account = "0x" + self.ix.ix_data[8 + 8 + 4:][:20].hex()
        pda_account = self.ix.get_account(1)
        code_account = self.ix.get_account(3)
        if code_account == str(SYS_PROGRAM_ID) or code_account == '':
            code_account = None

        account_info = NeonAccountInfo(neon_account, pda_account, code_account,
                                       self.ix.sign.slot, None, self.ix.sign.sign)
        self.debug(f"{account_info}")
        self.state.add_account_to_db(account_info)
        return True


class CreateAccount2IxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'CreateAccount2', state)

    def execute(self) -> bool:
        self._decoding_start()

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip("Ignore failed create account")

        if len(self.ix.ix_data) < 21:
            return self._decoding_skip(f'not enough data to get the Neon account {len(self.ix.ix_data)}')

        neon_account = "0x" + self.ix.ix_data[1:][:20].hex()
        pda_account = self.ix.get_account(2)
        code_account = self.ix.get_account(3)
        if code_account == '':
            code_account = None

        account_info = NeonAccountInfo(neon_account, pda_account, code_account,
                                       self.ix.sign.slot, None, self.ix.sign.sign)
        self.debug(f"{account_info}")
        self.state.add_account_to_db(account_info)
        return True


class ResizeStorageAccountIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ResizeStorageAccount', state)

    def execute(self) -> bool:
        self._decoding_start()

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip("Ignore failed resize account")

        pda_account = self.ix.get_account(0)
        code_account = self.ix.get_account(2)

        account_info = NeonAccountInfo(None, pda_account, code_account,
                                       self.ix.sign.slot, None, self.ix.sign.sign)
        self.debug(f"{account_info}")
        self.state.add_account_to_db(account_info)
        return True


class CallFromRawIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'CallFromRaw', state)

    def execute(self) -> bool:
        self._decoding_start()

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

        if len(self.ix.ix_data) < 92:
            return self._decoding_skip('no enough data to get the Neon tx')

        rlp_sign = self.ix.ix_data[25:90]
        rlp_data = self.ix.ix_data[90:]

        neon_tx = NeonTxInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        tx = NeonTxResult('')
        tx.neon_tx = neon_tx

        if decode_neon_tx_result(tx.neon_res, tx.neon_tx.sign, self.ix.tx, self.ix.evm_ix_idx).is_valid():
            return self._decoding_done(tx, 'found Neon results')

        return self._decode_tx(tx)


class OnResultIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'OnResult', state)

    def execute(self) -> bool:
        self._decoding_start()

        if self.ix.neon_obj is None:
            return self._decoding_skip('no transaction to add result')

        log = self.ix.ix_data

        status = '0x1' if log[1] < 0xd0 else '0x0'
        gas_used = hex(int.from_bytes(log[2:10], 'little'))
        return_value = log[10:].hex()

        self.ix.neon_obj.neon_res.set_result(self.ix.sign, status, gas_used, return_value)
        return self._decoding_done(self.ix.neon_obj, 'found Neon results')


class OnEventIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'OnEvent', state)

    def execute(self) -> bool:
        self._decoding_start()

        if self.ix.neon_obj is None:
            return self._decoding_skip('no transaction to add events')

        log = self.ix.ix_data

        address = log[1:21]
        count_topics = int().from_bytes(log[21:29], 'little')
        topics = []
        pos = 29
        for _ in range(count_topics):
            topic_bin = log[pos:pos + 32]
            topics.append('0x' + topic_bin.hex())
            pos += 32
        data = log[pos:]
        rec = {
            'address': '0x' + address.hex(),
            'topics': topics,
            'data': '0x' + data.hex(),
            'transactionIndex': hex(self.ix.sign.idx),
            'transactionHash': self.ix.neon_obj.neon_tx.sign,
        }

        self.ix.neon_obj.neon_res.append_record(rec)
        return True


class PartialCallIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallFromRawEthereumTX', state)

    def execute(self) -> bool:
        self._decoding_start()

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

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

        tx = self._getadd_tx(storage_account, blocked_accounts, neon_tx)
        self.ix.sign.set_steps(step_count)

        if decode_neon_tx_result(tx.neon_res, tx.neon_tx.sign, self.ix.tx, self.ix.evm_ix_idx).is_valid():
            return self._decoding_done(tx, 'found Neon results')

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

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

        if self.ix.get_account_cnt() < self._blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')
        if len(self.ix.ix_data) < 14:
            return self._decoding_skip('no enough data to get arguments')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(self._blocked_accounts_start)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')

        tx = self._getadd_tx(storage_account, blocked_accounts)
        if not tx:
            return self._decode_skip(f'no transaction at the storage {storage_account}')

        self.ix.sign.set_steps(step_count)

        if decode_neon_tx_result(tx.neon_res, tx.neon_tx.sign, self.ix.tx, self.ix.evm_ix_idx).is_valid():
            return self._decoding_done(tx, 'found Neon results')

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

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

        if self.ix.get_account_cnt() < self._blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')

        holder_account = self.ix.get_account(0)
        storage_account = self.ix.get_account(1)
        blocked_accounts = self.ix.get_account_list(self._blocked_accounts_start)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')

        tx = self._init_tx_from_holder(holder_account, storage_account, blocked_accounts)
        if not tx:
            return self._decoding_skip(f'fail to init in storage {storage_account} from holder {holder_account}')

        self.ix.sign.set_steps(step_count)

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

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

        blocked_accounts_start = 3
        if self.ix.get_account_cnt() < blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(blocked_accounts_start)

        tx = self._getadd_tx(storage_account, blocked_accounts)
        if not tx:
            return self._decoding_skip(f'cannot find tx in the storage {storage_account}')

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

        if SolReceiptParser(self.ix.tx).check_if_error():
            return self._decoding_skip(f'ignore failed {self.name} instruction')

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

        self.ix.sign.set_steps(step_count)

        if decode_neon_tx_result(tx.neon_res, tx.neon_tx.sign, self.ix.tx, self.ix.evm_ix_idx).is_valid():
            return self._decoding_done(tx, 'found Neon results')

        return self._decode_tx(tx)


class ExecuteOrContinueNoChainIdIxParser(ExecuteOrContinueIxParser):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterativeOrContinueNoChainId', state)


@logged_group("neon.Indexer")
class BlocksIndexer:
    def __init__(self, db: IndexerDB, solana: SolanaInteractor):
        self.db = db
        self.solana = solana
        self.counted_logger = MetricsToLogBuff()

    def gather_blocks(self):
        start_time = time.time()
        slot = self.solana.get_slot(FINALIZED)['result']
        self.db.set_latest_block(slot)
        gather_blocks_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.counted_logger.print(
            self.debug,
            list_params={"gather_blocks_ms": gather_blocks_ms},
            latest_params={"last_block_slot": slot}
        )


@logged_group("neon.Indexer")
class Indexer(IndexerBase):
    def __init__(self, solana_url, indexer_user: IIndexerUser):
        self.debug(f'Finalized commitment: {FINALIZED}')
        solana = SolanaInteractor(solana_url)
        self.db = IndexerDB(solana)
        last_known_slot = self.db.get_min_receipt_slot()
        IndexerBase.__init__(self, solana, last_known_slot)
        self.indexed_slot = self.last_slot
        self.min_used_slot = 0
        self._cancel_tx_executor = CancelTxExecutor(solana, get_solana_accounts()[0])
        self.block_indexer = BlocksIndexer(db=self.db, solana=solana)
        self.counted_logger = MetricsToLogBuff()
        self._user = indexer_user

        self.state = ReceiptsParserState(db=self.db, solana=solana, indexer_user=indexer_user)
        self.ix_decoder_map = {
            0x00: WriteIxDecoder(self.state),
            0x01: DummyIxDecoder('Finalize', self.state),
            0x02: CreateAccountIxDecoder(self.state),
            0x03: DummyIxDecoder('Call', self.state),
            0x04: DummyIxDecoder('CreateAccountWithSeed', self.state),
            0x05: CallFromRawIxDecoder(self.state),
            0x06: OnResultIxDecoder(self.state),
            0x07: OnEventIxDecoder(self.state),
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
            0x16: ExecuteTrxFromAccountV02IxDecoder(self.state),
            0x17: DummyIxDecoder('UpdateValidsTable', self.state),
            0x18: CreateAccount2IxDecoder(self.state),
            0x19: DummyIxDecoder('Deposit', self.state),
            0x1a: DummyIxDecoder('MigrateAccount', self.state),
            0x1b: ExecuteOrContinueNoChainIdIxParser(self.state)
        }
        self.def_decoder = DummyIxDecoder('Unknown', self.state)

    def process_functions(self):
        self.block_indexer.gather_blocks()
        IndexerBase.process_functions(self)
        self.process_receipts()
        self._cancel_tx_executor.execute_tx_list()
        self._cancel_tx_executor.clear()

    def process_receipts(self):
        start_time = time.time()
        last_block_slot = self.db.get_latest_block_slot()
        start_indexed_slot = self.indexed_slot

        max_slot = 1
        while max_slot > 0:
            max_slot = 0
            for slot, sign, tx in self.transaction_receipts.get_txs(self.indexed_slot, last_block_slot):
                max_slot = max(max_slot, slot)

                ix_info = SolanaIxInfo(sign=sign, slot=slot, tx=tx)

                for _ in ix_info.iter_ixs():
                    req_id = ix_info.sign.get_req_id()
                    with logging_context(sol_tx=req_id):
                        self.state.set_ix(ix_info)
                        (self.ix_decoder_map.get(ix_info.evm_ix) or self.def_decoder).execute()

                self.state.add_tx_cost(ix_info.cost_info)

            if max_slot > 0:
                self.indexed_slot = max_slot + 1
                self.min_used_slot = self.state.complete_done_objects(self.indexed_slot)

            self._process_status()

        was_skipped_tx = False
        # cancel transactions with long inactive time
        for tx in self.state.iter_txs():
            if tx.storage_account and (abs(tx.slot - self.indexed_slot) > CANCEL_TIMEOUT):
                if (not self.unlock_accounts(tx)) and (abs(tx.slot - self.indexed_slot) > SKIP_CANCEL_TIMEOUT):
                    self.debug(f'skip to cancel {tx}')
                    tx.neon_res.slot = self.indexed_slot
                    self.state.done_tx(tx)
                    was_skipped_tx = True

        if was_skipped_tx:
            self.min_used_slot = self.state.complete_done_objects(self.indexed_slot)

        process_receipts_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.counted_logger.print(
            self.debug,
            list_params={
                "process receipts ms": process_receipts_ms,
                "processed slots": self.indexed_slot - start_indexed_slot
            },
            latest_params={
                "transaction receipts len": self.transaction_receipts.size(),
                "indexed slot": self.indexed_slot,
                "min used slot": self.min_used_slot
            }
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

        storage = self.solana.get_storage_account_info(tx.storage_account)
        if not storage:
            self.warning(f"Storage {str(tx.storage_account)} for tx {tx.neon_tx.sign} is empty")
            return False

        if storage.caller != tx.neon_tx.addr[2:]:
            self.warning(f"Storage {str(tx.storage_account)} for tx {tx.neon_tx.sign} has another caller: " +
                         f"{str(storage.caller)} != {tx.neon_tx.addr[2:]}")
            return False

        tx_nonce = int(tx.neon_tx.nonce[2:], 16)
        if storage.nonce != tx_nonce:
            self.warning(f"Storage {str(tx.storage_account)} for tx {tx.neon_tx.sign} has another nonce: " +
                         f"{storage.nonce} != {tx_nonce}")
            return False

        if not len(storage.account_list):
            self.warning(f"Storage {str(tx.storage_account)} for tx {tx.neon_tx.sign} has empty account list.")
            return False

        if len(storage.account_list) != len(tx.blocked_accounts):
            self.warning(f"Transaction {tx.neon_tx} has another list of accounts than storage.")
            return False

        for (writable, account), (idx, tx_account) in zip(storage.account_list, enumerate(tx.blocked_accounts)):
            if account != tx_account:
                self.warning(f"Transaction {tx.neon_tx} has another list of accounts than storage: " +
                             f"{idx}: {account} != {tx_account}")
                return False

        self.debug(f'Neon tx is blocked: storage {tx.storage_account}, {tx.neon_tx}, {storage.account_list}')
        self._cancel_tx_executor.add_blocked_storage_account(storage)
        tx.canceled = True
        return True

    def _process_status(self):
        self._user.on_db_status(self.db.status())
        self._user.on_solana_rpc_status(self.solana.is_healthy())
