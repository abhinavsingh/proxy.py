import random
import base64

from eth_keys import keys as eth_keys
from hashlib import sha256
from solana.publickey import PublicKey
from spl.token.instructions import get_associated_token_address
from typing import NamedTuple

from .layouts import ACCOUNT_INFO_LAYOUT
from ..environment import neon_cli, ETH_TOKEN_MINT_ID, EVM_LOADER_ID
from .constants import ACCOUNT_SEED_VERSION
from solana.rpc.commitment import Confirmed


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
    state: int

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.ether, int.from_bytes(cont.trx_count, 'little'), PublicKey(cont.code_account), cont.state)


def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account, commitment=Confirmed)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) < expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data


def getAccountInfo(client, eth_account: EthereumAddress):
    account_sol, nonce = ether2program(eth_account)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)


def isPayed(client, address: str):
    acc_info: AccountInfo = getAccountInfo(client, EthereumAddress(address))
    return acc_info.state != 0
