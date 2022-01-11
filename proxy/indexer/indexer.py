from typing import Optional

import base58
import os
import time
import logging

try:
    from indexer_base import logger, IndexerBase, PARALLEL_REQUESTS
    from indexer_db import IndexerDB
    from utils import check_error, NeonIxSignInfo, NeonTxResultInfo, NeonTxSignInfo, Canceller, str_fmt_object
except ImportError:
    from .indexer_base import logger, IndexerBase, PARALLEL_REQUESTS
    from .indexer_db import IndexerDB
    from .utils import check_error, NeonIxSignInfo, NeonTxResultInfo, NeonTxAddrInfo, Canceller, str_fmt_object

from ..environment import EVM_LOADER_ID

CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", "60"))
UPDATE_BLOCK_COUNT = PARALLEL_REQUESTS * 16


class NeonIxInfo:
    def __init__(self, sign: bytes, slot: int, tx: {}):
        self.sign = NeonIxSignInfo(sign=sign, slot=slot, idx=-1)
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
            logger.debug(f'{self} fail to get a Neon EVM instruction: {e}')
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
        for self.sign.idx, self.ix in tx_ixs:
            if 'programIdIndex' not in self.ix:
                logger.debug(f'{self} error: fail to get program id')
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
        self.used_ixs = set()
        self.slot = 0

    def mark_ix_used(self, ix_info: NeonIxInfo):
        self.used_ixs.add(ix_info.sign.copy())
        self.slot = max(self.slot, ix_info.sign.slot)

    def move_ix_used(self, obj):
        self.used_ixs.update(obj.used_ixs)
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
    def __init__(self, storage_account: str, neon_tx: NeonTxAddrInfo, neon_res: NeonTxResultInfo):
        BaseEvmObject.__init__(self)
        self.storage_account = storage_account
        self.neon_tx = (neon_tx or NeonTxAddrInfo())
        self.neon_res = (neon_res or NeonTxResultInfo())
        self.step_count = []
        self.holder_account = ''
        self.blocked_accounts = []

    def __str__(self):
        return str_fmt_object(self)


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

    On parsing the instruction is stored into the intermediate object (holder, transaction) and in the _used_ixs set.
    If an error occurs while decoding, the decoder can skip this instruction.

    So, in the _used_ixs set the parser stores all instructions needed for assembling intermediate objects. After
    each cycle the parser stores the number of the smallest slot from the _used_ixs set. That is why, the parser can be
    restarted in any moment.

    After restarting the parser:
    - Restores the intermediate state of objects;
    - And continues the decoding process.

    When the whole Neon transaction is assembled:
    - Neon transaction is stored into the DB;
    - All instructions used for assembly the transaction are stored into the DB;
    - All instructions are removed from the _used_ixs set;
    - If number of the smallest slot in the _used_ixs is changed, it's stored into the DB for the future restart.
    """
    def __init__(self, db: IndexerDB, client):
        self._db = db
        self._client = client
        self._holder_table = {}
        self._tx_table = {}
        self._done_tx_list = []
        self._used_ixs = set()
        self.ix = NeonIxInfo(sign=bytes(), slot=-1, tx=None)

    def set_ix(self, ix_info: NeonIxInfo):
        self.ix = ix_info

    def mark_ix_used(self):
        self._used_ixs.add(self.ix.sign.copy())

    def unmark_ix_used(self, obj: BaseEvmObject):
        self._used_ixs.difference_update(obj.used_ixs)

    def get_holder(self, account: str) -> Optional[NeonHolderObject]:
        return self._holder_table.get(account)

    def add_holder(self, account: str) -> NeonHolderObject:
        if account in self._holder_table:
            logger.debug(f'{self.ix} ATTENTION: the holder {account} is already used!')

        holder = NeonHolderObject(account=account)
        self._holder_table[account] = holder
        return holder

    def del_holder(self, holder: NeonHolderObject):
        self._holder_table.pop(holder.account, None)

    def get_tx(self, account: str) -> Optional[NeonTxObject]:
        return self._tx_table.get(account)

    def add_tx(self, storage_account: str, neon_tx=None, neon_res=None) -> NeonTxObject:
        if storage_account in self._tx_table:
            logger.debug(f'{self.ix} ATTENTION: the tx {storage_account} is already used!')

        tx = NeonTxObject(storage_account=storage_account, neon_tx=neon_tx, neon_res=neon_res)
        self._tx_table[storage_account] = tx
        return tx

    def del_tx(self, tx: NeonTxObject):
        self._tx_table.pop(tx.storage_account, None)

    def done_tx(self, tx: NeonTxObject):
        self._done_tx_list.append(tx)

    def save_tx(self, tx: NeonTxObject):
        self._db.submit_transaction(self._client, tx.neon_tx, tx.neon_res, tx.used_ixs)

    def done_tx(self, obj: BaseEvmObject):
        # Continue waiting of ixs with the same neon tx, because the parsing order can be other than the execution order
        obj.mark_ix_used(self.ix)
        self._done_tx_list.append(obj)

    def complete_done_txs(self):
        for tx in self._done_tx_list:
            self.unmark_ix_used(tx)
            self.save_tx(tx)
            self.del_tx(tx)
        self._done_tx_list.clear()

    def iter_txs(self) -> NeonTxObject:
        for tx in self._tx_table.values():
            yield tx


class DummyIxDecoder:
    def __init__(self, name: str, state: ReceiptsParserState):
        self.name = name
        self.state = state

    def __str__(self):
        return f'{self.name} {self.state.ix}'

    @staticmethod
    def neon_addr_fmt(neon_tx: NeonTxAddrInfo):
        return f'Neon tx {neon_tx.sign}, Neon addr {neon_tx.addr}'

    def _getadd_tx(self, storage_account, neon_tx=None, blocked_accounts=[str]) -> NeonTxObject:
        tx = self.state.get_tx(storage_account)
        if tx:
            if neon_tx and tx.neon_tx and neon_tx.sign != tx.neon_tx.sign:
                self._log_error(f'storage {storage_account}, tx.neon_tx({tx.neon_tx}) != neon_tx({neon_tx})')
                self.state.unmark_ix_used(tx)
                self.state.del_tx(tx)
                tx = None
            elif tx.blocked_accounts != blocked_accounts:
                self._log_error('blocked accounts not equal')

        if not tx:
            tx = self.state.add_tx(storage_account, neon_tx)
            tx.blocked_accounts = blocked_accounts

        return tx

    def _log_error(self, msg: str):
        logger.error(f'{self} error: {msg}')

    def _decoding_start(self):
        """
        Start decoding process:
        - get the instruction from the parser state;
        - log the start of decoding.
        """
        self.ix = self.state.ix
        logger.debug(f'{self} ...')

    def _decoding_success(self, obj: BaseEvmObject, msg: str) -> bool:
        """
        The instruction has been successfully parsed:
        - Mark the instruction as used;
        - log the success message.
        """
        obj.mark_ix_used(self.ix)
        logger.debug(f'{self}: {obj}')

        self.state.mark_ix_used()
        logger.debug(f'{self}: {msg}')
        return True

    def _decoding_done(self, obj: BaseEvmObject, msg: str) -> bool:
        """
        Assembling of the object has been successfully finished.
        """
        logger.debug(f'{self}: {obj}')
        if isinstance(obj, NeonTxObject):
            obj.mark_ix_used(self.ix)
            self.state.done_tx(obj)
        elif isinstance(obj, NeonHolderObject):
            self.state.unmark_ix_used(obj)
            self.state.del_holder(obj)

        else:
            assert False, 'Unknown type of object'
        logger.debug(f'{self}: {msg}')
        return True

    def _decoding_skip(self, reason: str) -> bool:
        """Skip decoding of the instruction"""
        logger.error(f'{self}: {reason}')
        return False

    def _decoding_fail(self, obj: BaseEvmObject, reason: str) -> bool:
        """
        Assembling of objects has been failed:
        - destroy the intermediate objects;
        - unmark all instructions as unused.
        """
        logger.error(f'{self}: {reason}')
        self.state.unmark_ix_used(obj)

        logger.error(f'{self}: {obj}')
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
            res_error = tx.neon_res.decode(self.ix.tx)
            if res_error:
                return self._decoding_fail(tx, f'Neon results error "{res_error}"')
            if tx.neon_res.is_valid():
                return self._decoding_done(tx, f'storage {tx.storage_account}, {self.neon_addr_fmt(tx.neon_tx)}')
        return self._decoding_success(tx, f'storage {tx.storage_account}, {self.neon_addr_fmt(tx.neon_tx)}')

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
            self._log_error(f'Neon tx rlp error "{rlp_error}"')

        tx.holder_account = holder_account
        tx.move_ix_used(holder)
        self._decoding_done(holder, f'holder {holder.account}, {self.neon_addr_fmt(tx.neon_tx)}')
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

    def _decode_datachunck(self, ix_info: NeonIxInfo) -> _DataChunk:
        # No enough bytes to get length of chunk
        if len(ix_info.ix_data) < 17:
            return self._DataChunk()

        return self._DataChunk(
            offset=int.from_bytes(ix_info.ix_data[4:8], "little"),
            length=int.from_bytes(ix_info.ix_data[8:16], "little"),
            data=ix_info.ix_data[16:],
        )

    def execute(self) -> bool:
        # if instruction_data[0] == 0x00 or instruction_data[0] == 0x12:
        # write_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        #
        # if write_account in holder_table:
        #     storage_account = holder_table[write_account].storage_account
        #     if storage_account in continue_table:
        #         continue_table[storage_account].signatures.append(signature)
        #
        #     if instruction_data[0] == 0x00:
        #         offset = int.from_bytes(instruction_data[4:8], "little")
        #         length = int.from_bytes(instruction_data[8:16], "little")
        #         data = instruction_data[16:]
        #     if instruction_data[0] == 0x12:
        #         offset = int.from_bytes(instruction_data[9:13], "little")
        #         length = int.from_bytes(instruction_data[13:21], "little")
        #         data = instruction_data[21:]
        #
        #     # logger.debug("WRITE offset {} length {}".format(offset, length))
        #
        #     if holder_table[write_account].max_written < (offset + length):
        #         holder_table[write_account].max_written = offset + length
        #
        #     for index in range(length):
        #         holder_table[write_account].data[1 + offset + index] = data[index]
        #         holder_table[write_account].count_written += 1
        #
        #     if holder_table[write_account].max_written == holder_table[write_account].count_written:
        #         # logger.debug("WRITE {} {}".format(holder_table[write_account].max_written, holder_table[write_account].count_written))
        #         signature = holder_table[write_account].data[1:66]
        #         length = int.from_bytes(holder_table[write_account].data[66:74], "little")
        #         unsigned_msg = holder_table[write_account].data[74:74 + length]
        #
        #         try:
        #             (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, signature)
        #             if len(eth_trx) / 2 > holder_table[write_account].max_written:
        #                 logger.debug(
        #                     "WRITE got {} exp {}".format(len(eth_trx), holder_table[write_account].max_written))
        #                 continue
        #
        #             if storage_account in continue_table:
        #                 continue_result = continue_table[storage_account]
        #
        #                 # logger.debug(eth_signature)
        #                 trx_table[eth_signature] = TransactionStruct(
        #                     eth_trx,
        #                     eth_signature,
        #                     from_address,
        #                     continue_result.results,
        #                     continue_result.signatures,
        #                     storage_account,
        #                     continue_result.accounts,
        #                     [slot] + continue_result.slot
        #                 )
        #
        #                 del continue_table[storage_account]
        #             else:
        #                 logger.error("Storage not found")
        #                 logger.error(f"{eth_signature} unknown")
        #                 # raise
        #
        #             del holder_table[write_account]
        #         except rlp.exceptions.RLPException:
        #             # logger.debug("rlp.exceptions.RLPException")
        #             pass
        #         except Exception as err:
        #             if str(err).startswith("nonhashable type"):
        #                 # logger.debug("nonhashable type")
        #                 pass
        #             elif str(err).startswith("unsupported operand type"):
        #                 # logger.debug("unsupported operand type")
        #                 pass
        #             else:
        #                 logger.debug("could not parse trx {}".format(err))
        #                 raise
        self._decoding_start()

        chunk = self._decode_datachunck(self.ix)
        if not chunk.is_valid():
            return self._decoding_skip('bad data chunk')
        if self.ix.get_account_cnt() < 1:
            return self._decoding_skip('no enough accounts')

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

        return self._decoding_success(holder, f'holder {holder.account}')


class WriteWithHolderIxDecoder(WriteIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'WriteWithHolder', state)

    def _decode_datachunck(self, ix_info: NeonIxInfo) -> WriteIxDecoder._DataChunk:
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
        # elif instruction_data[0] == 0x05:
        # sign = instruction_data[25:90]
        # unsigned_msg = instruction_data[90:]
        #
        # (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)
        #
        # got_result = get_trx_results(trx)
        # if got_result is not None:
        #     # self.submit_transaction(eth_trx, eth_signature, from_address, got_result, [signature])
        #     trx_table[eth_signature] = TransactionStruct(
        #         eth_trx,
        #         eth_signature,
        #         from_address,
        #         got_result,
        #         [signature],
        #         None,
        #         None,
        #         [slot]
        #     )
        # else:
        #     logger.error("RESULT NOT FOUND IN 05\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))
        self._decoding_start()

        if len(self.ix.ix_data) < 92:
            return self._decoding_skip('no enough data to get the Neon tx')

        rlp_sign = self.ix.ix_data[25:90]
        rlp_data = self.ix.ix_data[90:]

        neon_tx = NeonTxAddrInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        neon_res = NeonTxResultInfo(self.ix.tx)
        if neon_res.error:
            return self._decoding_skip(f'Neon results error "{neon_res.error}"')

        tx = NeonTxObject('', neon_tx=neon_tx, neon_res=neon_res)
        return self._decoding_done(tx, self.neon_addr_fmt(neon_tx))


class PartialCallIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallFromRawEthereumTX', state)

    def execute(self) -> bool:
        # elif instruction_data[0] == 0x09 or instruction_data[0] == 0x13:  # PartialCallFromRawEthereumTX PartialCallFromRawEthereumTXv02
        # storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        # blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                     instruction['accounts'][7:]]
        #
        # # collateral_pool_buf = instruction_data[1:5]
        # # step_count = instruction_data[5:13]
        # # from_addr = instruction_data[13:33]
        #
        # sign = instruction_data[33:98]
        # unsigned_msg = instruction_data[98:]
        #
        # (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)
        #
        # trx_table[eth_signature] = TransactionStruct(
        #     eth_trx,
        #     eth_signature,
        #     from_address,
        #     None,
        #     [signature],
        #     storage_account,
        #     blocked_accounts,
        #     [slot]
        # )
        #
        # if storage_account in continue_table:
        #     continue_result = continue_table[storage_account]
        #     if continue_result.accounts != blocked_accounts:
        #         logger.error("Strange behavior. Pay attention. BLOCKED ACCOUNTS NOT EQUAL")
        #     trx_table[eth_signature].got_result = continue_result.results
        #     trx_table[eth_signature].signatures += continue_result.signatures
        #     trx_table[eth_signature].slot += continue_result.slot
        #
        #     del continue_table[storage_account]
        self._decoding_start()

        if self.ix.get_account_cnt() < 8:
            return self._decoding_skip('no enough accounts')
        if len(self.ix.ix_data) < 100:
            return self._decoding_skip('no enough data to get the Neon tx')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(7)
        step_count = int.from_bytes(self.ix.ix_data[5:13], 'little')
        rlp_sign = self.ix.ix_data[33:98]
        rlp_data = self.ix.ix_data[98:]

        neon_tx = NeonTxAddrInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        tx = self._getadd_tx(storage_account, neon_tx=neon_tx, blocked_accounts=blocked_accounts)
        tx.step_count.append(step_count)
        return self._decode_tx(tx)


class PartialCallV02IxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallFromRawEthereumTXv02', state)


class ContinueIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'Continue', state)
        self._blocked_accounts_start = 5

    def execute(self) -> bool:
        # elif instruction_data[0] == 0x0a or instruction_data[0] == 0x14:  # Continue or ContinueV02
        # seen_slots.add(slot)
        #
        # storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        # if instruction_data[0] == 0x0a:
        #     # logger.debug("{:>10} {:>6} Continue 0x{}".format(slot, counter, instruction_data.hex()))
        #     blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                         instruction['accounts'][5:]]
        # if instruction_data[0] == 0x14:
        #     # logger.debug("{:>10} {:>6} ContinueV02 0x{}".format(slot, counter, instruction_data.hex()))
        #     blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                         instruction['accounts'][6:]]
        # got_result = get_trx_results(trx)
        #
        # if storage_account in continue_table:
        #     continue_table[storage_account].signatures.append(signature)
        #     continue_table[storage_account].slot.append(slot)
        #
        #     if got_result is not None:
        #         if continue_table[storage_account].results is not None:
        #             logger.error(
        #                 "Strange behavior. Pay attention. RESULT ALREADY EXISTS IN CONTINUE TABLE")
        #         if continue_table[storage_account].accounts != blocked_accounts:
        #             logger.error("Strange behavior. Pay attention. BLOCKED ACCOUNTS NOT EQUAL")
        #
        #         continue_table[storage_account].results = got_result
        # else:
        #     continue_table[storage_account] = ContinueStruct(signature, got_result, [slot],
        #                                                      blocked_accounts)
        #
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


class ContinueV02IxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ContinueV02', state)
        self._blocked_accounts_start = 6


class ExecuteTrxFromAccountIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterative', state)
        self._blocked_accounts_start = 5

    def execute(self) -> bool:
        # elif instruction_data[0] == 0x0b or instruction_data[0] == 0x16:  # ExecuteTrxFromAccountDataIterative ExecuteTrxFromAccountDataIterativeV02
        # seen_slots.add(slot)
        # if instruction_data[0] == 0x0b:
        #     # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterative 0x{}".format(slot, counter, instruction_data.hex()))
        #     blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                         instruction['accounts'][5:]]
        # if instruction_data[0] == 0x16:
        #     # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterativeV02 0x{}".format(slot, counter, instruction_data.hex()))
        #     blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                         instruction['accounts'][7:]]
        #
        # holder_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        # storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]
        #
        # if storage_account in continue_table:
        #     continue_table[storage_account].signatures.append(signature)
        #     continue_table[storage_account].slot.append(slot)
        #
        #     if holder_account in holder_table:
        #         if holder_table[holder_account].storage_account != storage_account:
        #             logger.error("Strange behavior. Pay attention. STORAGE_ACCOUNT != STORAGE_ACCOUNT")
        #             holder_table[holder_account] = HolderStruct(storage_account)
        #     else:
        #         holder_table[holder_account] = HolderStruct(storage_account)
        # else:
        #     continue_table[storage_account] = ContinueStruct(signature, None, [slot], blocked_accounts)
        #     holder_table[holder_account] = HolderStruct(storage_account)
        #
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


class ExecuteTrxFromAccountV02IxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterativeV02', state)
        self._blocked_accounts_start = 7


class CancelIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'Cancel', state)

    def execute(self) -> bool:
        # elif instruction_data[0] == 0x0c or instruction_data[0] == 0x15:  # Cancel
        # seen_slots.add(slot)
        # # logger.debug("{:>10} {:>6} Cancel 0x{}".format(slot, counter, instruction_data.hex()))
        #
        # storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        # blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                     instruction['accounts'][6:]]
        #
        # continue_table[storage_account] = ContinueStruct(signature, ([], "0x0", 0, [], slot), [slot], blocked_accounts)
        self._decoding_start()

        blocked_accounts_start = 6
        if self.ix.get_account_cnt() < blocked_accounts_start + 1:
            return self._decoding_skip('no enough accounts')

        storage_account = self.ix.get_account(0)
        blocked_accounts = self.ix.get_account_list(blocked_accounts_start)

        tx = self._getadd_tx(storage_account, blocked_accounts=blocked_accounts)
        if not tx.neon_tx.is_valid():
            return self._decoding_fail(tx, 'unknown Neon tx')

        tx.neon_res.clear()
        tx.neon_res.slot = self.ix.sign.slot
        return self._decoding_done(tx, f'storage {storage_account}, {self.neon_addr_fmt(tx.neon_tx)}')


class CancelV02IxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'CancelV02', state)


class PartialCallOrContinueIxDecoder(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'PartialCallOrContinueFromRawEthereumTX', state)

    def execute(self) -> bool:
        # elif instruction_data[0] == 0x0d:
        # seen_slots.add(slot)
        # logger.debug("{:>10} {:>6} PartialCallOrContinueFromRawEthereumTX 0x{}".format(slot, counter,
        #                                                                                instruction_data.hex()))
        #
        # storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        # blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                     instruction['accounts'][7:]]
        # got_result = get_trx_results(trx)
        #
        # # collateral_pool_buf = instruction_data[1:5]
        # # step_count = instruction_data[5:13]
        # # from_addr = instruction_data[13:33]
        #
        # sign = instruction_data[33:98]
        # unsigned_msg = instruction_data[98:]
        #
        # (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)
        #
        # if eth_signature in trx_table:
        #     trx_table[eth_signature].slot.append(slot)
        #     if got_result is not None:
        #         trx_table[eth_signature].got_result = got_result
        #         trx_table[eth_signature].signatures.append(signature)
        #     else:
        #         trx_table[eth_signature].signatures.insert(0, signature)
        # else:
        #     trx_table[eth_signature] = TransactionStruct(
        #         eth_trx,
        #         eth_signature,
        #         from_address,
        #         got_result,
        #         [signature],
        #         storage_account,
        #         blocked_accounts,
        #         [slot]
        #     )
        #
        # if storage_account in continue_table:
        #     continue_result = continue_table[storage_account]
        #     trx_table[eth_signature].signatures += continue_result.signatures
        #     trx_table[eth_signature].slot += continue_result.slot
        #     if continue_result.results is not None:
        #         if trx_table[eth_signature].got_result is not None:
        #             logger.error(
        #                 "Strange behavior. Pay attention. RESULT ALREADY EXISTS IN CONTINUE TABLE")
        #         trx_table[eth_signature].got_result = continue_result.results
        #
        #     del continue_table[storage_account]
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

        neon_tx = NeonTxAddrInfo(rlp_sign=rlp_sign, rlp_data=rlp_data)
        if neon_tx.error:
            return self._decoding_skip(f'Neon tx rlp error "{neon_tx.error}"')

        tx = self._getadd_tx(storage_account, neon_tx=neon_tx, blocked_accounts=blocked_accounts)
        tx.step_count.append(step_count)
        return self._decode_tx(tx)


class ExecuteOrContinueIxParser(DummyIxDecoder):
    def __init__(self, state: ReceiptsParserState):
        DummyIxDecoder.__init__(self, 'ExecuteTrxFromAccountDataIterativeOrContinue', state)

    def execute(self) -> bool:
        # elif instruction_data[0] == 0x0e:
        # seen_slots.add(slot)
        # # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterativeOrContinue 0x{}".format(slot, counter, instruction_data.hex()))
        #
        # holder_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
        # storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]
        # blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in
        #                     instruction['accounts'][7:]]
        # got_result = get_trx_results(trx)
        #
        # if storage_account in continue_table:
        #     continue_table[storage_account].slot.append(slot)
        #
        #     if holder_account in holder_table:
        #         if holder_table[holder_account].storage_account != storage_account:
        #             logger.error("Strange behavior. Pay attention. STORAGE_ACCOUNT != STORAGE_ACCOUNT")
        #             holder_table[holder_account] = HolderStruct(storage_account)
        #     else:
        #         logger.error("Strange behavior. Pay attention. HOLDER ACCOUNT NOT FOUND")
        #         holder_table[holder_account] = HolderStruct(storage_account)
        #
        #     if got_result is not None:
        #         if continue_table[storage_account].results is not None:
        #             logger.error(
        #                 "Strange behavior. Pay attention. RESULT ALREADY EXISTS IN CONTINUE TABLE")
        #         if continue_table[storage_account].accounts != blocked_accounts:
        #             logger.error("Strange behavior. Pay attention. BLOCKED ACCOUNTS NOT EQUAL")
        #
        #         continue_table[storage_account].results = got_result
        #         continue_table[storage_account].signatures.append(signature)
        #     else:
        #         continue_table[storage_account].signatures.insert(0, signature)
        # else:
        #     continue_table[storage_account] = ContinueStruct(signature, got_result, [slot],
        #                                                      blocked_accounts)
        #     holder_table[holder_account] = HolderStruct(storage_account)
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


class Indexer(IndexerBase):
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 log_level = 'INFO'):
        IndexerBase.__init__(self, solana_url, evm_loader_id, log_level, 0)
        self.db = IndexerDB()
        self.canceller = Canceller()
        self.blocked_storages = {}
        self.processed_slot = 0

    def process_functions(self):
        IndexerBase.process_functions(self)
        logger.debug("Process receipts")
        self.process_receipts()
        logger.debug("Start getting blocks")
        self.gather_blocks()
        logger.debug("Unlock accounts")
        self.canceller.unlock_accounts(self.blocked_storages)
        self.blocked_storages = {}

    def process_receipts(self):
        start_time = time.time()

        state = ReceiptsParserState(db=self.db, client=self.client)
        ix_decoder_map = {
            0x00: WriteIxDecoder(state),
            0x01: DummyIxDecoder('Finalize', state),
            0x02: DummyIxDecoder('CreateAccount', state),
            0x03: DummyIxDecoder('Call', state),
            0x04: DummyIxDecoder('CreateAccountWithSeed', state),
            0x05: CallFromRawIxDecoder(state),
            0x06: DummyIxDecoder('OnEvent', state),
            0x07: DummyIxDecoder('OnResult', state),
            0x09: PartialCallIxDecoder(state),
            0x0a: ContinueIxDecoder(state),
            0x0b: ExecuteTrxFromAccountIxDecoder(state),
            0x0c: CancelIxDecoder(state),
            0x0d: PartialCallOrContinueIxDecoder(state),
            0x0e: ExecuteOrContinueIxParser(state),
            0x12: WriteWithHolderIxDecoder(state),
            0x13: PartialCallV02IxDecoder(state),
            0x14: ContinueV02IxDecoder(state),
            0x15: CancelV02IxDecoder(state),
            0x16: ExecuteTrxFromAccountV02IxDecoder(state)
        }
        def_decoder = DummyIxDecoder('Unknown', state)

        max_slot = 0
        for slot, sign, tx in self.transaction_receipts.get_trxs(self.processed_slot, reverse=False):
            if max_slot != slot:
                state.complete_done_txs()
                max_slot = max(max_slot, slot)

            ix_info = NeonIxInfo(slot=slot, sign=sign, tx=tx)

            for _ in ix_info.iter_ixs():
                state.set_ix(ix_info)
                (ix_decoder_map.get(ix_info.evm_ix) or def_decoder).execute()

        # after last instruction and slot
        state.complete_done_txs()

        for tx in state.iter_txs():
            if tx.storage_account and abs(tx.slot - self.current_slot) > CANCEL_TIMEOUT:
                logger.debug(f'Neon tx is blocked: storage {tx.storage_account}, {tx.neon_tx}')
                self.blocked_storages[tx.storage_account] = (tx.neon_tx.rlp_tx, tx.blocked_accounts)

        self.processed_slot = max(self.processed_slot, max_slot + 1)

        process_receipts_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        logger.debug(f"process_receipts_ms: {process_receipts_ms} transaction_receipts.len: {self.transaction_receipts.size()} from {self.processed_slot} to {self.current_slot} slots")

    def gather_blocks(self):
        start_time = time.time()
        last_block_slot = self.db.get_last_block_slot()
        max_height = self.db.get_last_block_height()
        height = -1
        confirmed_blocks_len = 10000
        client = self.client._provider
        list_opts = {"commitment": "finalized"}
        block_opts = {"commitment": "finalized", "transactionDetails": "none", "rewards": False}
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
                logger.warning(f"FAILED max_height {max_height} last_block_slot {last_block_slot} {last_block}")
                break

            # Everything is good
            logger.debug(f"gather_blocks from {height} to {max_height}")
            self.db.fill_block_height(height, confirmed_blocks)
            self.db.set_last_slot_height(last_block_slot, max_height)
            height = max_height

        gather_blocks_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        logger.debug(f"gather_blocks_ms: {gather_blocks_ms} last_height: {max_height} last_block_slot {last_block_slot}")


def run_indexer(solana_url,
                evm_loader_id,
                log_level = 'DEBUG'):
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id},
        log_level: {log_level}""")

    indexer = Indexer(solana_url,
                      evm_loader_id,
                      log_level)
    indexer.run()


if __name__ == "__main__":
    solana_url = os.environ.get('SOLANA_URL', 'http://localhost:8899')
    evm_loader_id = os.environ.get('EVM_LOADER_ID', '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io')
    log_level = os.environ.get('LOG_LEVEL', 'INFO')

    run_indexer(solana_url,
                evm_loader_id,
                log_level)
