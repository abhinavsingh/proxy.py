from __future__ import annotations

import random

from eth_keys import keys as eth_keys
from hashlib import sha256
from solana.publickey import PublicKey
from spl.token.instructions import get_associated_token_address
from typing import NamedTuple

from .layouts import ACCOUNT_INFO_LAYOUT
from ..environment import ETH_TOKEN_MINT_ID, EVM_LOADER_ID
from .constants import ACCOUNT_SEED_VERSION


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
    result = PublicKey(sha256(bytes(base) + bytes(seed) + bytes(PublicKey(EVM_LOADER_ID))).digest())
    return result


def ether2program(ether):
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


def getTokenAddr(account):
    return get_associated_token_address(PublicKey(account), ETH_TOKEN_MINT_ID)


class AccountInfoLayout(NamedTuple):
    ether: eth_keys.PublicKey
    trx_count: int
    code_account: PublicKey
    state: int

    def is_payed(self) -> bool:
        return self.state != 0

    @staticmethod
    def frombytes(data) -> AccountInfoLayout:
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfoLayout(cont.ether, int.from_bytes(cont.trx_count, 'little'),
                                 PublicKey(cont.code_account), cont.state)
