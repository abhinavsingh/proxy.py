from __future__ import annotations

import random

from typing import Tuple

from eth_keys import keys as eth_keys
from hashlib import sha256
from solana.publickey import PublicKey

from .environment_data import EVM_LOADER_ID
from .constants import ACCOUNT_SEED_VERSION


class EthereumAddress:
    def __init__(self, data, private: eth_keys.PrivateKey = None):
        if isinstance(data, str):
            data = bytes(bytearray.fromhex(data[2:]))
        self.data = data
        self.private = private

    @staticmethod
    def random() -> EthereumAddress:
        letters = '0123456789abcdef'
        data = bytearray.fromhex(''.join([random.choice(letters) for k in range(64)]))
        pk = eth_keys.PrivateKey(data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    @staticmethod
    def from_private_key(pk_data: bytes) -> EthereumAddress:
        pk = eth_keys.PrivateKey(pk_data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    def __str__(self):
        return '0x'+self.data.hex()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self): return self.data


def accountWithSeed(base: bytes, seed: bytes) -> PublicKey:
    result = PublicKey(sha256(bytes(base) + bytes(seed) + bytes(PublicKey(EVM_LOADER_ID))).digest())
    return result


def ether2program(ether) -> Tuple[PublicKey, int]:

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
    return pda, nonce
