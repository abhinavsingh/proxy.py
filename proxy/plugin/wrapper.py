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

def create_program_address(seeds, programId):
    seeds_str = ' '.join([s.hex() for s in seeds])
#    print(seeds_str)
    result = subprocess.check_output([
            '/mnt/working/solana/solana.git/target/debug/solana',
            'create-program-address',
            seeds_str,
            programId])
#    print(result)
    (account, nonce) = result.decode('utf8').split('  ')
#    print(account, nonce)
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
    "account" / PUBLIC_KEY_LAYOUT,
    "eth_acc" / Bytes(20),
    "nonce" / Int8ul,
)

INITIALIZE_AUTH_LAYOUT = cStruct(
    "instruction" / Int8ul,
    "account" / PUBLIC_KEY_LAYOUT,
    "eth_token" / Bytes(20),
    "eth_acc" / Bytes(20),
    "nonce" / Int8ul,
)

ACCOUNT_INFO_LAYOUT = cStruct(
    "account" / PUBLIC_KEY_LAYOUT,
    "eth_acc" / Bytes(20),
    "trx_count" / Int32ul,
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
    account: PublicKey
    eth_acc: eth_keys.PublicKey
    trx_count: int

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(PublicKey(cont.account), cont.eth_acc, cont.trx_count)


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

    def getAccountInfo(self, eth_token):
        (token_info, nonce) = create_program_address([bytes(eth_token)], self.program)

        info = self.client.get_account_info(token_info)['result']['value']
        if info is None:
            raise Exception("Can't get inforamtion about {}".format(token_info))

        if info['owner'] != self.program:
            raise Exception("Wrong owner for account {}".format(token_info))

        data = base64.b64decode(info['data'][0])
        if len(data) != ACCOUNT_INFO_LAYOUT.sizeof():
            raise Exception("Wrong data length for account {}".format(token_info))

        return AccountInfo.frombytes(data)

    def getTokenDecimals(self, token):
        mint = self.client.get_account_info(token)['result']['value']
        
        if mint['owner'] != 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA':
            raise Exception("Invalid owner for token {}".format(token))

        data = base64.b64decode(mint['data'][0])
        if len(data) != 82:
            raise Exception("Invalid data length for token {}".format(token))

        return int.from_bytes(data[36+8:36+8+1], "little")


    def transfer(self, eth_token, eth_acc, source, destination, amount):
        token_program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
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
                AccountMeta(pubkey=token_program, is_signer=False, is_writable=False),
                AccountMeta(pubkey=source, is_signer=False, is_writable=True),
                AccountMeta(pubkey=destination, is_signer=False, is_writable=True),
                AccountMeta(pubkey=authority, is_signer=False, is_writable=False)])


    def getBalanceInfo(self, eth_token, eth_acc):
        (account_info, nonce) = create_program_address([bytes(eth_token), bytes(eth_acc)], self.program)

        info = self.client.get_account_info(account_info)['result']['value']
        if info is None:
            raise Exception("Can't get information about {}".format(account_info))

        if info['owner'] != self.program:
            raise Exception("Wrong owner for account {}".format(account_info))

        data = base64.b64decode(info['data'][0])
        if len(data) != BALANCE_INFO_LAYOUT.sizeof():
            raise Exception("Wrong data length for account {}".format(account_info))

        return BalanceInfo.frombytes(data)


    def initializeAccount(self, account, eth_acc, signer_key):
        (account_info, nonce) = create_program_address([bytes(eth_acc)], self.program)
#        print('InitializeAccount:', account_info, nonce)
        data = INITIALIZE_ACCOUNT_LAYOUT.build(dict(
            instruction=0,
            account=bytes(account),
            eth_acc=bytes(eth_acc),
            nonce=nonce,
        ))
        return TransactionInstruction(program_id=self.program, data=data, keys=[
                AccountMeta(pubkey=account_info, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.program, is_signer=False, is_writable=False),
                AccountMeta(pubkey=system_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=signer_key, is_signer=True, is_writable=True),
            ])

    def initializeAuthority(self, account, eth_token, eth_acc, signer_key):
        (account_info, nonce) = create_program_address([bytes(eth_token), bytes(eth_acc)], self.program)
#        print("InitializeAuthority:", account_info)

        data = INITIALIZE_AUTH_LAYOUT.build(dict(
            instruction=1,
            account=bytes(account),
            eth_token=bytes(eth_token),
            eth_acc=bytes(eth_acc),
            nonce=nonce,
        ))
        return TransactionInstruction(program_id=self.program, data=data, keys=[
                AccountMeta(pubkey=account_info, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.program, is_signer=False, is_writable=False),
                AccountMeta(pubkey=system_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=signer_key, is_signer=True, is_writable=True),
            ])
