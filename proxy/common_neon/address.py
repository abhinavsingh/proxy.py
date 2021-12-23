import logging
import random

from eth_keys import keys as eth_keys
from hashlib import sha256
from solana.publickey import PublicKey
from spl.token.instructions import get_associated_token_address
from typing import NamedTuple

from .layouts import ACCOUNT_INFO_LAYOUT
from ..environment import neon_cli, ETH_TOKEN_MINT_ID, EVM_LOADER_ID
from .constants import ACCOUNT_SEED_VERSION

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


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


class AccountInfo(NamedTuple):
    ether: eth_keys.PublicKey
    trx_count: int
    code_account: PublicKey

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.ether, cont.trx_count, PublicKey(cont.code_account))
