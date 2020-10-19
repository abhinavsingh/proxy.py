from typing import NamedTuple
from solana.rpc.api import Client
from solana.account import Account
from solana.publickey import PublicKey
from solana._layouts.shared import PUBLIC_KEY_LAYOUT, RUST_STRING_LAYOUT
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
import base58
import base64
from construct import Bytes, Int8ul, Int32ul, Int64ul, Pass  # type: ignore
from construct import Struct as cStruct
import subprocess
from eth_keys import keys as eth_keys
import random

system_id = '11111111111111111111111111111111'
rent_id = 'SysvarRent111111111111111111111111111111111'
token_id = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

def create_program_address(seeds, programId):
    seeds_str = ' '.join([s.hex() for s in seeds])
    result = subprocess.check_output([
            '/mnt/working/solana/solana.git/target/debug/solana',
            'create-program-address',
            seeds_str,
            programId])
    (account, nonce) = result.decode('utf8').split('  ')
    return account, int(nonce)

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

INITIALIZE_ACCOUNT_LAYOUT = cStruct(
    "instruction" / Int8ul,
    "eth_acc" / Bytes(20),
    "nonce" / Int8ul,
)

INITIALIZE_TOKEN_LAYOUT = cStruct(
    "instruction" / Int8ul,
    "token" / PUBLIC_KEY_LAYOUT,
    "eth_token" / Bytes(20),
    "nonce" / Int8ul,
)

INITIALIZE_BALANCE_LAYOUT = cStruct(
    "instruction" / Int8ul,
    "account" / PUBLIC_KEY_LAYOUT,
    "eth_token" / Bytes(20),
    "eth_acc" / Bytes(20),
    "nonce" / Int8ul,
)

ACCOUNT_INFO_LAYOUT = cStruct(
    "eth_acc" / Bytes(20),
    "trx_count" / Int32ul,
)

TOKEN_INFO_LAYOUT = cStruct(
    "token" / PUBLIC_KEY_LAYOUT,
    "eth_token" / Bytes(20),
)

BALANCE_INFO_LAYOUT = cStruct(
    "account" / PUBLIC_KEY_LAYOUT,
    "eth_token" / Bytes(20),
    "eth_acc" / Bytes(20),
)

TRANSFER_LAYOUT = cStruct(
    "instruction" / Int8ul,
    "amount" / Int64ul,
    "nonce" / Int8ul,
    "eth_token" / Bytes(20),
    "eth_acc" / Bytes(20),
)

class AccountInfo(NamedTuple):
    eth_acc: eth_keys.PublicKey
    trx_count: int

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.eth_acc, cont.trx_count)

class TokenInfo(NamedTuple):
    token: PublicKey
    eth_token: eth_keys.PublicKey

    @staticmethod
    def frombytes(data):
        cont = TOKEN_INFO_LAYOUT.parse(data)
        return TokenInfo(PublicKey(cont.token), cont.eth_token)

class BalanceInfo(NamedTuple):
    account: PublicKey
    eth_token: bytes
    eth_acc: bytes

    @staticmethod
    def frombytes(data):
        cont = BALANCE_INFO_LAYOUT.parse(data)
        return BalanceInfo(PublicKey(cont.account), cont.eth_token.hex(), cont.eth_acc.hex())


class WrapperProgram():
    def __init__(self, client, program):
        self.program = program
        self.client = client

    def program_address(self, seeds):
        return create_program_address(seeds, self.program)

    def _getAccountData(self, account, expected_length, owner=None):
        info = self.client.get_account_info(account)['result']['value']
        if info is None:
            raise Exception("Can't get information about {}".format(account))

        if info['owner'] != (owner or self.program):
            raise Exception("Invalid owner for account data {}".format(account))

        data = base64.b64decode(info['data'][0])
        if len(data) != expected_length:
            raise Exception("Wrong data length for account data {}".format(account))

        return data

    def getAccountInfo(self, eth_acc):
        (account_info, nonce) = create_program_address([bytes(eth_acc)], self.program)
        data = self._getAccountData(account_info, ACCOUNT_INFO_LAYOUT.sizeof())
        return AccountInfo.frombytes(data)

    def getTokenInfo(self, eth_token):
        (token_info, nonce) = create_program_address([bytes(eth_token)], self.program)
        data = self._getAccountData(token_info, TOKEN_INFO_LAYOUT.sizeof())
        return TokenInfo.frombytes(data)

    def getBalanceInfo(self, eth_token, eth_acc):
        (account_info, nonce) = create_program_address([bytes(eth_token), bytes(eth_acc)], self.program)
        data = self._getAccountData(account_info, BALANCE_INFO_LAYOUT.sizeof())
        return BalanceInfo.frombytes(data)

    def getTokenDecimals(self, token):
        data = self._getAccountData(token, 82, owner=token_id)
        return int.from_bytes(data[36+8:36+8+1], "little")

    def transfer(self, eth_token, eth_acc, source, destination, amount):
        print('--- transfer:', eth_token, eth_acc, source, destination, amount)
        (authority, nonceAuthority) = create_program_address([bytes(eth_token), bytes(eth_acc)], self.program)
        data = TRANSFER_LAYOUT.build(dict(
            instruction=3,
            amount=amount,
            nonce=nonceAuthority,
            eth_token=bytes(eth_token),
            eth_acc=bytes(eth_acc),
        ))
        return TransactionInstruction(program_id=self.program, data=data, keys=[
                AccountMeta(pubkey=token_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=source, is_signer=False, is_writable=True),
                AccountMeta(pubkey=destination, is_signer=False, is_writable=True),
                AccountMeta(pubkey=authority, is_signer=False, is_writable=False)])



    def initializeAccount(self, eth_acc, signer_key):
        (account_info, nonce) = create_program_address([bytes(eth_acc)], self.program)
        data = INITIALIZE_ACCOUNT_LAYOUT.build(dict(
            instruction=0,
            eth_acc=bytes(eth_acc),
            nonce=nonce,
        ))
        return TransactionInstruction(program_id=self.program, data=data, keys=[
                AccountMeta(pubkey=account_info, is_signer=True, is_writable=True),
                AccountMeta(pubkey=system_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=rent_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=signer_key, is_signer=True, is_writable=True),
            ])

    def initializeToken(self, token, eth_token, signer_key):
        (token_info, nonce) = create_program_address([bytes(eth_token)], self.program)
        data = INITIALIZE_TOKEN_LAYOUT.build(dict(
            instruction=1,
            token=bytes(token),
            eth_token=bytes(eth_token),
            nonce=nonce,
        ))
        return TransactionInstruction(program_id=self.program, data=data, keys=[
                AccountMeta(pubkey=token_info, is_signer=True, is_writable=True),
                AccountMeta(pubkey=system_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=rent_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=signer_key, is_signer=True, is_writable=True),
            ])

    def initializeBalance(self, account, eth_token, eth_acc, signer_key):
        (account_info, nonce) = create_program_address([bytes(eth_token), bytes(eth_acc)], self.program)

        data = INITIALIZE_BALANCE_LAYOUT.build(dict(
            instruction=2,
            account=bytes(account),
            eth_token=bytes(eth_token),
            eth_acc=bytes(eth_acc),
            nonce=nonce,
        ))
        return TransactionInstruction(program_id=self.program, data=data, keys=[
                AccountMeta(pubkey=account_info, is_signer=False, is_writable=True),
                AccountMeta(pubkey=system_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=rent_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=signer_key, is_signer=True, is_writable=True),
            ])
