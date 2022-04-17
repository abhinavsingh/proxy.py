from __future__ import annotations
from typing import Dict, Any, Optional

import json
import base58

from eth_utils import big_endian_to_int

#TODO: move it out from here
from ...environment import EVM_LOADER_ID

from ..eth_proto import Trx as EthTx


def str_fmt_object(obj) -> str:
    def lookup(o) -> Optional[Dict]:
        if hasattr(o, '__str_dict__'):
            return o.__str_dict__()
        elif hasattr(o, '__dict__'):
            return o.__dict__
        return None

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

    def __str_dict__(self) -> Dict:
        return {
            'slot': self.slot,
            'is_finalized': self.is_finalized,
            'is_fake': self.is_fake,
            'hash': self.hash,
            'parent_hash': self.parent_hash,
            'time': self.time,
            'len(signs)': len(self.signs)
        }

    def __getstate__(self) -> Dict:
        return self.__dict__

    def __setstate__(self, src):
        self.__dict__ = src

    def is_empty_fake(self) -> bool:
        return self.is_fake and (len(self.signs) == 0)

    def is_empty(self) -> bool:
        return self.time is None


class NeonTxResultInfo:
    def __init__(self, neon_sign='', tx=None, ix_idx=-1):
        if not isinstance(tx, dict):
            self._set_defaults()
        else:
            self.decode(neon_sign, tx, ix_idx)

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

    def _decode_event(self, neon_sign, log, tx_idx):
        log_idx = len(self.logs)
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
            'transactionLogIndex': hex(log_idx),
            'transactionIndex': hex(tx_idx),
            'logIndex': hex(log_idx),
            'transactionHash': neon_sign,
            # 'blockNumber': block_number, # set when transaction found
            # 'blockHash': block_hash # set when transaction found
        }
        self.logs.append(rec)

    def _decode_return(self, log: bytes, ix_idx: int, tx: {}):
        self.status = '0x1' if log[1] < 0xd0 else '0x0'
        self.gas_used = hex(int.from_bytes(log[2:10], 'little'))
        self.return_value = log[10:].hex()
        self.sol_sign = tx['transaction']['signatures'][0]
        self.slot = tx['slot']
        self.idx = ix_idx

    def fill_block_info(self, block: SolanaBlockInfo):
        self.slot = block.slot
        self.block_hash = block.hash
        for rec in self.logs:
            rec['blockHash'] = block.hash
            rec['blockNumber'] = hex(block.slot)

    def decode(self, neon_sign: str, tx: {}, ix_idx=-1) -> NeonTxResultInfo:
        self._set_defaults()
        meta_ixs = tx['meta']['innerInstructions']
        msg = tx['transaction']['message']
        accounts = msg['accountKeys']

        for inner_ix in meta_ixs:
            ix_idx = inner_ix['index']
            for event in inner_ix['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                    log = base58.b58decode(event['data'])
                    evm_ix = int(log[0])
                    if evm_ix == 7:
                        self._decode_event(neon_sign, log, ix_idx)
                    elif evm_ix == 6:
                        self._decode_return(log, ix_idx, tx)
        return self

    def canceled(self, tx: {}):
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
