from __future__ import annotations
from typing import Dict, Any, List, Optional, cast
from enum import Enum
from logged_groups import logged_group
from eth_utils import big_endian_to_int

import json

from ..environment_data import LOG_FULL_OBJECT_INFO
from ..eth_proto import Trx as NeonTx


def str_fmt_object(obj: Any) -> str:
    type_name = 'Type'
    class_prefix = "<class '"

    def lookup(d: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in d.items():
            if callable(value):
                continue

            key = key.lstrip('_')
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
            elif isinstance(value, list) or isinstance(value, set):
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
            elif hasattr(value, '__str__'):
                value_str = str(value)
                if value_str.startswith(f'<{type_name} ') and hasattr(value, '__dict__'):
                    result[key] = lookup(value.__dict__)
                else:
                    result[key] = value_str
            else:
                result[key] = value
        return result

    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    if name.startswith(class_prefix):
        name = name[len(class_prefix):]

    if hasattr(obj, '__dict__'):
        members = json.dumps(lookup(obj.__dict__), skipkeys=True, sort_keys=True)
    elif isinstance(obj, dict):
        members = json.dumps(lookup(obj), skipkeys=True, sort_keys=True)
    else:
        members = None

    return f'<{type_name} {name}>: {members}'


# TODO: move to separate file
class SolanaBlockInfo:
    def __init__(self, block_slot: int, block_hash: Optional[str] = None, block_time: Optional[int] = None,
                 parent_block_slot: Optional[int] = None, parent_block_hash: Optional[str] = None,
                 is_finalized=False):
        self._block_slot = block_slot
        self._is_finalized = is_finalized
        self._block_hash = block_hash
        self._block_time = block_time
        self._parent_block_slot = parent_block_slot
        self._parent_block_hash = parent_block_hash

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict[str, Any]:
        return self.__dict__

    def __setstate__(self, src) -> None:
        self.__dict__ = src

    def set_finalized(self, value: bool) -> None:
        self._is_finalized = value

    def set_block_hash(self, block_hash: str) -> None:
        self._block_hash = block_hash

    @property
    def block_slot(self) -> int:
        return self._block_slot

    @property
    def block_hash(self) -> Optional[str]:
        return self._block_hash

    @property
    def block_time(self) -> Optional[int]:
        return self._block_time

    @property
    def is_finalized(self) -> bool:
        return self._is_finalized

    @property
    def parent_block_slot(self) -> Optional[int]:
        return self._parent_block_slot

    @property
    def parent_block_hash(self) -> Optional[str]:
        return self._parent_block_hash

    def is_empty(self) -> bool:
        return self.block_time is None


# TODO: move to separate file
@logged_group("neon.Parser")
class NeonTxResultInfo:
    def __init__(self):
        self.log_list: List[Dict[str, Any]] = []
        self._status = ''
        self._gas_used = ''
        self._return_value = ''
        self._sol_sig: Optional[str] = None
        self._tx_idx: Optional[int] = None
        self._block_slot: Optional[int] = None
        self._block_hash: Optional[str] = None
        self._sol_ix_idx: Optional[int] = None
        self._sol_ix_inner_idx: Optional[int] = None

    @property
    def block_slot(self) -> Optional[int]:
        return self._block_slot

    @property
    def block_hash(self) -> Optional[str]:
        return self._block_hash

    @property
    def tx_idx(self) -> Optional[int]:
        return self._tx_idx

    @property
    def status(self) -> str:
        return self._status

    @property
    def gas_used(self) -> str:
        return self._gas_used

    @property
    def return_value(self) -> str:
        return self._return_value

    @property
    def sol_sig(self) -> Optional[str]:
        return self._sol_sig

    @property
    def sol_ix_idx(self) -> Optional[int]:
        return self._sol_ix_idx

    @property
    def sol_ix_inner_idx(self) -> Optional[int]:
        return self._sol_ix_inner_idx

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict[str, Any]:
        return self.__dict__

    def __setstate__(self, src) -> None:
        self.__dict__ = src

    def append_record(self, rec: Dict[str, Any]) -> None:
        self.log_list.append(rec)

    def fill_result(self, status: str, gas_used: str, return_value: str) -> None:
        self._status = status
        self._gas_used = gas_used
        self._return_value = return_value

    def fill_sol_sig_info(self, sol_sig: str, sol_ix_idx: int, sol_ix_inner_idx: int) -> None:
        self._sol_sig = sol_sig
        self._sol_ix_idx = sol_ix_idx
        self._sol_ix_inner_idx = sol_ix_inner_idx

    def fill_block_info(self, block: SolanaBlockInfo, tx_idx: int, log_idx: int) -> None:
        hex_block_slot = hex(block.block_slot)
        hex_tx_idx = hex(tx_idx)

        self._block_slot = block.block_slot
        self._block_hash = block.block_hash
        self._tx_idx = tx_idx
        for rec in self.log_list:
            rec['blockHash'] = block.block_hash
            rec['blockNumber'] = hex_block_slot
            rec['transactionIndex'] = hex_tx_idx
            rec['logIndex'] = hex(log_idx)
            log_idx += 1

    def is_valid(self) -> bool:
        return self._gas_used != ''


# TODO: move to separate file
class NeonTxInfo:
    def __init__(self, *, tx: Optional[NeonTx] = None,
                 rlp_sig: Optional[bytes] = None, rlp_data: Optional[bytes] = None):
        self._addr: Optional[str] = None
        self._sig = ''
        self._nonce = ''
        self._gas_price = ''
        self._gas_limit = ''
        self._to_addr: Optional[str] = None
        self._contract: Optional[str] = None
        self._value = ''
        self._calldata = ''
        self._v = ''
        self._r = ''
        self._s = ''
        self._error: Optional[Exception] = None

        if isinstance(rlp_sig, bytes) and isinstance(rlp_data, bytes):
            assert tx is None
            self._decode(cast(bytes, rlp_sig), cast(bytes, rlp_data))
        elif isinstance(tx, NeonTx):
            assert rlp_sig is None
            assert rlp_data is None
            self._init_from_eth_tx(cast(NeonTx, tx))

    @property
    def addr(self) -> Optional[str]:
        return self._addr

    @property
    def to_addr(self) -> Optional[str]:
        return self._to_addr

    @property
    def contract(self) -> Optional[str]:
        return self._contract

    @property
    def sig(self) -> str:
        return self._sig

    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def gas_price(self) -> str:
        return self._gas_price

    @property
    def gas_limit(self) -> str:
        return self._gas_limit

    @property
    def value(self) -> str:
        return self._value

    @property
    def calldata(self) -> str:
        return self._calldata

    @property
    def v(self) -> str:
        return self._v

    @property
    def r(self) -> str:
        return self._r

    @property
    def s(self) -> str:
        return self._s

    @property
    def error(self) -> Optional[Exception]:
        return self._error

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict[str, Any]:
        return self.__dict__

    def __setstate__(self, src) -> None:
        self.__dict__ = src

    def _init_from_eth_tx(self, tx: NeonTx):
        self._v = hex(tx.v)
        self._r = hex(tx.r)
        self._s = hex(tx.s)

        self._sig = '0x' + tx.hash_signed().hex()
        self._addr = '0x' + tx.sender()

        self._nonce = hex(tx.nonce)
        self._gas_price = hex(tx.gasPrice)
        self._gas_limit = hex(tx.gasLimit)
        self._value = hex(tx.value)
        self._calldata = '0x' + tx.callData.hex()

        if not tx.toAddress:
            self._to_addr = None
            self._contract = '0x' + tx.contract()
        else:
            self._to_addr = '0x' + tx.toAddress.hex()
            self._contract = None

    def _decode(self, rlp_sig: bytes, rlp_data: bytes) -> NeonTxInfo:
        try:
            utx = NeonTx.fromString(rlp_data)

            if utx.v == 0:
                uv = int(rlp_sig[64]) + 27
            else:
                uv = int(rlp_sig[64]) + 35 + 2 * utx.v
            ur = big_endian_to_int(rlp_sig[0:32])
            us = big_endian_to_int(rlp_sig[32:64])

            tx = NeonTx(utx.nonce, utx.gasPrice, utx.gasLimit, utx.toAddress, utx.value, utx.callData, uv, ur, us)
            self._init_from_eth_tx(tx)
        except Exception as e:
            self._error = e
        return self

    def is_valid(self):
        return (self._addr is not None) and (self._error is None)


# TODO: move to separate file
class NeonTxReceiptInfo:
    def __init__(self, neon_tx: NeonTxInfo, neon_tx_res: NeonTxResultInfo):
        self._neon_tx = neon_tx
        self._neon_tx_res = neon_tx_res

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __getstate__(self) -> Dict[str, Any]:
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    @property
    def neon_tx(self) -> NeonTxInfo:
        return self._neon_tx

    @property
    def neon_tx_res(self) -> NeonTxResultInfo:
        return self._neon_tx_res


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


def get_holder_msg(eth_trx: NeonTx) -> bytes:
    unsigned_msg = eth_trx.unsigned_msg()
    return eth_trx.signature() + len(unsigned_msg).to_bytes(8, byteorder="little") + unsigned_msg
