from __future__ import annotations

from typing import Dict, Any, Optional, List
import json
from enum import Enum

from logged_groups import logged_group
from eth_utils import big_endian_to_int

from proxy.indexer.utils import SolanaIxSignInfo
# TODO: move it out from here
from ..environment_data import EVM_LOADER_ID, LOG_FULL_OBJECT_INFO
from ..eth_proto import Trx as EthTx


def str_fmt_object(obj) -> str:
    def lookup(obj) -> Optional[Dict]:
        if not hasattr(obj, '__dict__'):
            return None

        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, Enum):
                value = str(value)
                idx = value.find('.')
                if idx != -1:
                    value = value[idx + 1:]
                result[key] = value
            elif LOG_FULL_OBJECT_INFO:
                result[key] = value
            elif value is None:
                pass
            elif isinstance(value, bool):
                if value:
                    result[key] = value
            elif isinstance(value, List):
                if len(value) > 0:
                    result[f'len({key})'] = len(value)
            elif isinstance(value, str) or isinstance(value, bytes) or isinstance(value, bytearray):
                if len(value) == 0:
                    continue
                if isinstance(value, bytes) or isinstance(value, bytearray):
                    value = '0x' + value.hex()
                if len(value) > 130:
                    value = value[:130] + '...'
                result[key] = value
            else:
                result[key] = value
        return result

    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    members = json.dumps(obj, skipkeys=True, default=lookup, sort_keys=True)
    return f'{name}: {members}'


class SolanaBlockInfo:
    def __init__(self, slot: int, is_finalized=False, hash=None, parent_hash=None, time=None, signs=None, is_fake=False):
        self.slot = slot
        self.is_finalized = is_finalized
        self.is_fake = is_fake
        self.hash = hash
        self.parent_hash = parent_hash
        self.time = time
        self.signs = (signs or [])

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict:
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    def is_empty_fake(self) -> bool:
        return self.is_fake and (len(self.signs) == 0)

    def is_empty(self) -> bool:
        return self.time is None


@logged_group("neon.Parser")
class NeonTxResultInfo:
    def __init__(self):
        self._set_defaults()

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    def _set_defaults(self):
        self.logs = []
        self.status = "0x0"
        self.gas_used = '0x0'
        self.return_value = bytes()
        self.sol_sign = None
        self.slot = -1
        self.block_hash = ''
        self.idx = -1

    def append_record(self, rec):
        log_idx = len(self.logs)
        rec['transactionLogIndex'] = hex(log_idx)
        rec['logIndex'] = hex(log_idx)
        self.logs.append(rec)

    def set_result(self, sign: SolanaIxSignInfo, status, gas_used, return_value):
        self.status = status
        self.gas_used = gas_used
        self.return_value = return_value
        self.sol_sign = sign.sign
        self.slot = sign.slot
        self.idx = sign.idx

    def fill_block_info(self, block: SolanaBlockInfo):
        self.slot = block.slot
        self.block_hash = block.hash
        for rec in self.logs:
            rec['blockHash'] = block.hash
            rec['blockNumber'] = hex(block.slot)

    def decode(self, neon_sig: str, tx: {}, ix_idx=-1) -> NeonTxResultInfo:
        self._set_defaults()
        meta = tx['meta']
        meta_ixs = meta['innerInstructions']
        msg = tx['transaction']['message']

        accounts = msg['accountKeys']
        lookup_accounts = meta.get('loadedAddresses', None)
        if lookup_accounts is not None:
            accounts += lookup_accounts['writable'] + lookup_accounts['readonly']

        for inner_ix in meta_ixs:
            ix_idx = inner_ix['index']
            for event in inner_ix['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                    log = base58.b58decode(event['data'])
                    evm_ix = int(log[0])
                    if evm_ix == 7:
                        self._decode_event(neon_sig, log, ix_idx)
                    elif evm_ix == 6:
                        self._decode_return(log, ix_idx, tx)
        return self

    def canceled(self, tx: Dict[Any, Any]):
        self._set_defaults()
        self.sol_sign = tx['transaction']['signatures'][0]
        self.slot = tx['slot']

    def is_valid(self) -> bool:
        return self.slot != -1


class NeonTxInfo:
    def __init__(self, rlp_sign=None, rlp_data=None):
        self.tx_idx = 0

        self._set_defaults()
        if isinstance(rlp_sign, bytes) and isinstance(rlp_data, bytes):
            self.decode(rlp_sign, rlp_data)

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    def _set_defaults(self):
        self.addr = None
        self.sign = None
        self.nonce = None
        self.gas_price = None
        self.gas_limit = None
        self.to_addr = None
        self.contract = None
        self.value = None
        self.calldata = None
        self.v = None
        self.r = None
        self.s = None
        self.error = None

    def init_from_eth_tx(self, tx: EthTx):
        self.v = hex(tx.v)
        self.r = hex(tx.r)
        self.s = hex(tx.s)

        self.sign = '0x' + tx.hash_signed().hex()
        self.addr = '0x' + tx.sender()

        self.nonce = hex(tx.nonce)
        self.gas_price = hex(tx.gasPrice)
        self.gas_limit = hex(tx.gasLimit)
        self.value = hex(tx.value)
        self.calldata = '0x' + tx.callData.hex()

        if not tx.toAddress:
            self.to_addr = None
            self.contract = '0x' + tx.contract()
        else:
            self.to_addr = '0x' + tx.toAddress.hex()
            self.contract = None

    def decode(self, rlp_sign: bytes, rlp_data: bytes) -> NeonTxInfo:
        self._set_defaults()

        try:
            utx = EthTx.fromString(rlp_data)

            if utx.v == 0:
                uv = int(rlp_sign[64]) + 27
            else:
                uv = int(rlp_sign[64]) + 35 + 2 * utx.v
            ur = big_endian_to_int(rlp_sign[0:32])
            us = big_endian_to_int(rlp_sign[32:64])

            tx = EthTx(utx.nonce, utx.gasPrice, utx.gasLimit, utx.toAddress, utx.value, utx.callData, uv, ur, us)
            self.init_from_eth_tx(tx)
        except Exception as e:
            self.error = e
        return self

    def clear(self):
        self._set_defaults()

    def is_valid(self):
        return (self.addr is not None) and (not self.error)


class NeonTxFullInfo:
    def __init__(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, used_ixs=[]):
        self.neon_tx = neon_tx
        self.neon_res = neon_res
        self.used_ixs = used_ixs

    def __str__(self):
        return str_fmt_object(self)

    def __getstate__(self):
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src


def get_from_dict(src: Dict, *path) -> Any:
    """Provides smart getting values from python dictionary"""
    val = src
    for key in path:
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val


def get_holder_msg(eth_trx: EthTx) -> bytes:
    unsigned_msg = eth_trx.unsigned_msg()
    return eth_trx.signature() + len(unsigned_msg).to_bytes(8, byteorder="little") + unsigned_msg
