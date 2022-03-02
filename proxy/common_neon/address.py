from __future__ import annotations

import random

from eth_keys import keys as eth_keys
from hashlib import sha256
from solana.publickey import PublicKey
from typing import NamedTuple

class EthereumAddress:
    def __init__(self, data, private=None):
        if isinstance(data, str):
            data = bytes(bytearray.fromhex(data[2:]))
        self.data = data
        self.private = private

    @staticmethod
    def random():
        letters = '0123456789abcdef'
        data = bytearray.fromhex(''.join([random.choice(letters) for k in range(64)]))
        pk = eth_keys.PrivateKey(data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    def __str__(self):
        return '0x'+self.data.hex()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self): return self.data


def accountWithSeed(base, seed):
    from ..environment import EVM_LOADER_ID

    result = PublicKey(sha256(bytes(base) + bytes(seed) + bytes(PublicKey(EVM_LOADER_ID))).digest())
    return result


def ether2program(ether):
    from .constants import ACCOUNT_SEED_VERSION
    from ..environment import EVM_LOADER_ID

    if isinstance(ether, str):
        pass
    elif isinstance(ether, EthereumAddress):
        ether = str(ether)
    else:
        ether = ether.hex()

    if ether[0:2] == '0x':
        ether = ether[2:]
    seed = [ACCOUNT_SEED_VERSION,  bytes.fromhex(ether)]
    (pda, nonce) = PublicKey.find_program_address(seed, PublicKey(EVM_LOADER_ID))
    return str(pda), nonce


class AccountInfoLayout(NamedTuple):
    ether: eth_keys.PublicKey
    balance: int
    trx_count: int
    code_account: PublicKey

    def is_payed(self) -> bool:
        return self.state != 0

    @staticmethod
    def frombytes(data) -> AccountInfoLayout:
        from .layouts import ACCOUNT_INFO_LAYOUT

        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfoLayout(
            ether=cont.ether, 
            balance=int.from_bytes(cont.balance, "little"),
            trx_count=int.from_bytes(cont.trx_count, "little"),
            code_account=PublicKey(cont.code_account)
        )
