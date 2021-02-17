from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from solana.sysvar import *
import time
import subprocess
import os
import base64
from eth_keys import keys as eth_keys
from typing import NamedTuple
from construct import Bytes, Int8ul, Int32ul, Int64ul, Pass  # type: ignore
from construct import Struct as cStruct
import random
import json
from sha3 import keccak_256
import struct

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
evm_loader_id = os.environ.get("EVM_LOADER", "3EvDG5aTfN4csM57WjxymnovHpyojZQExM6HZ9FmCgve")
sender_eth = "cf9f430be7e6c473ec1556004650328c71051bd4"
location_bin = ".deploy_contract.bin"

tokenkeg = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
sysvarclock = "SysvarC1ock11111111111111111111111111111111"
system_id = '11111111111111111111111111111111'
keccak_id = "KeccakSecp256k11111111111111111111111111111"
sysvar_id = "Sysvar1nstructions1111111111111111111111111"


ACCOUNT_INFO_LAYOUT = cStruct(
    "eth_acc" / Bytes(20),
    "trx_count" / Int32ul,
)

class AccountInfo(NamedTuple):
    eth_acc: eth_keys.PublicKey
    trx_count: int

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.eth_acc, cont.trx_count)

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


class solana_cli:
    def __init__(self, url):
        self.url = url

    def call(self, arguments):
        cmd = 'solana --url {} {}'.format(self.url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: solana error {}".format(err))
            raise

def confirm_transaction(client, tx_sig):
    """Confirm a transaction."""
    TIMEOUT = 30  # 30 seconds  pylint: disable=invalid-name
    elapsed_time = 0
    while elapsed_time < TIMEOUT:
        sleep_time = 3
        if not elapsed_time:
            sleep_time = 7
            time.sleep(sleep_time)
        else:
            time.sleep(sleep_time)
        resp = client.get_confirmed_transaction(tx_sig)
        if resp["result"]:
#            print('Confirmed transaction:', resp)
            break
        elapsed_time += sleep_time
    if not resp["result"]:
        raise RuntimeError("could not confirm transaction: ", tx_sig)
    return resp

def solana2ether(public_key):
    from web3 import Web3
    return bytes(Web3.keccak(bytes.fromhex(public_key))[-20:])

def create_program_address(seed, program_id):
    cli = solana_cli(solana_url)
    output = cli.call("create-program-address {} {}".format(seed, program_id))
    items = output.rstrip().split('  ')
    return (items[0], int(items[1]))



def unpack(data):
    ch = data[0]
    if (ch <= 0x7F):
        return (ch, data[1:])
    elif (ch == 0x80):
        return (None, data[1:])
    elif (ch <= 0xB7):
        l = ch - 0x80
        return (data[1:1+l].tobytes(), data[1+l:])
    elif (ch <= 0xBF):
        lLen = ch - 0xB7
        l = int.from_bytes(data[1:1+lLen], byteorder='little')
        return (data[1+lLen:1+lLen+l].tobytes(), data[1+lLen+l:])
    elif (ch == 0xC0):
        return ((), data[1:])
    elif (ch <= 0xF7):
        l = ch - 0xC0
        lst = list()
        sub = data[1:1+l]
        while len(sub):
            (item, sub) = unpack(sub)
            lst.append(item)
        return (lst, data[1+l:])
    else:
        lLen = ch - 0xF7
        l = int.from_bytes(data[1:1+lLen], byteorder='little')
        lst = list()
        sub = data[1+lLen:1+lLen+l]
        while len(sub):
            (item, sub) = unpack(sub)
            lst.append(item)
        return (lst, data[1+lLen+l:])

def pack(data):
    if data == None:
        return (0x80).to_bytes(1,'big')
    if isinstance(data, str):
        return pack(data.encode('utf8'))
    elif isinstance(data, bytes):
        if len(data) <= 55:
            return (len(data)+0x80).to_bytes(1,'big')+data
        else:
            l = len(data)
            lLen = (l.bit_length()+7)//8
            return (0xB7+lLen).to_bytes(1,'big')+l.to_bytes(lLen,'big')+data
    elif isinstance(data, int):
        if data < 0x80:
            return data.to_bytes(1,'big')
        else:
            l = (data.bit_length()+7)//8
            return (l + 0x80).to_bytes(1,'big') + data.to_bytes(l,'big')
        pass
    elif isinstance(data, list) or isinstance(data, tuple):
        if len(data) == 0:
            return (0xC0).to_bytes(1,'big')
        else:
            res = bytearray()
            for d in data:
                res += pack(d)
            l = len(res)
            if l <= 0x55:
                return (l + 0xC0).to_bytes(1,'big')+res
            else:
                lLen = (l.bit_length()+7)//8
                return (lLen+0xF7).to_bytes(1,'big') + l.to_bytes(lLen,'big') + res
    else:
        raise Exception("Unknown type {} of data".format(str(type(data))))

def getInt(a):
    if isinstance(a, int): return a
    if isinstance(a, bytes): return int.from_bytes(a, 'big')
    if a == None: return a
    raise Exception("Invalid convertion from {} to int".format(a))


class Trx:
    def __init__(self):
        self.nonce = None
        self.gasPrice = None
        self.gasLimit = None
        self.toAddress = None
        self.value = None
        self.callData = None
        self.v = None
        self.r = None
        self.s = None

    @classmethod
    def fromString(cls, s):
        t = Trx()
        (unpacked, data) = unpack(memoryview(s))
        (nonce, gasPrice, gasLimit, toAddress, value, callData, v, r, s) = unpacked
        t.nonce = getInt(nonce)
        t.gasPrice = getInt(gasPrice)
        t.gasLimit = getInt(gasLimit)
        t.toAddress = toAddress
        t.value = getInt(value)
        t.callData = callData
        t.v = getInt(v)
        t.r = getInt(r)
        t.s = getInt(s)
        return t

    def chainId(self):
        # chainid*2 + 35  xxxxx0 + 100011   xxxx0 + 100010 +1
        # chainid*2 + 36  xxxxx0 + 100100   xxxx0 + 100011 +1
        return (self.v-1)//2 - 17

    def __str__(self):
        return pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            self.v,
            self.r.to_bytes(32,'big') if self.r else None,
            self.s.to_bytes(32,'big') if self.s else None)
        ).hex()

    def get_msg(self, chainId=None):
        trx = pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            chainId or self.chainId(), None, None))
        return trx

    def hash(self, chainId=None):
        trx = pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            chainId or self.chainId(), None, None))
        return keccak_256(trx).digest()

    def sender(self):
        msgHash = self.hash()
        sig = eth_keys.Signature(vrs=[1 if self.v%2==0 else 0, self.r, self.s])
        pub = sig.recover_public_key_from_msg_hash(msgHash)
        return pub.to_canonical_address().hex()

def call_updated(trx_data, evm_loader, acc, client):
    _trx = Trx.fromString(bytearray.fromhex(trx_data[2:]))

    raw_msg = _trx.get_msg()
    msgHash = _trx.hash()
    sig = eth_keys.Signature(vrs=[1 if _trx.v % 2 == 0 else 0, _trx.r, _trx.s])
    pub = sig.recover_public_key_from_msg_hash(msgHash)

    check_count = 1
    data_start = 1 + 11
    eth_address_size = 20
    signature_size = 65
    eth_address_offset = data_start
    signature_offset = eth_address_offset + eth_address_size
    message_data_offset = signature_offset + signature_size

    data = struct.pack("B", check_count)
    data += struct.pack("<H", signature_offset)
    data += struct.pack("B", 0)
    data += struct.pack("<H", eth_address_offset)
    data += struct.pack("B", 0)
    data += struct.pack("<H", message_data_offset)
    data += struct.pack("<H", len(raw_msg))
    data += struct.pack("B", 0)
    data += pub.to_canonical_address()
    data += sig.to_bytes()
    data += raw_msg

    trx = Transaction().add(
        TransactionInstruction(program_id=keccak_id, data=data, keys=[
            AccountMeta(pubkey=PublicKey(keccak_id), is_signer=False,
                        is_writable=False),
        ])).add(
        TransactionInstruction(program_id=evm_loader,
                               data=(bytearray.fromhex("a2") + bytearray.fromhex(trx_data[2:])), keys=[
                AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(sysvar_id), is_signer=False,
                            is_writable=False),
            ]))
    result = client.send_transaction(trx, acc)
    result = confirm_transaction(client, result["result"])
    messages = result["result"]["meta"]["logMessages"]
    return (messages[messages.index("Program log: succeed") + 1], result)


def call(input, evm_loader, program, caller, acc, client):
    trx = Transaction().add(
        TransactionInstruction(program_id=evm_loader, data=input, keys=
        [
            AccountMeta(pubkey=program, is_signer=False, is_writable=True),
            AccountMeta(pubkey=caller, is_signer=False, is_writable=True),
            AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
            AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
        ]))

    result = client.send_transaction(trx, acc)
    result = confirm_transaction(client, result["result"])
    messages = result["result"]["meta"]["logMessages"]
    return (messages[messages.index("Program log: succeed") + 1], result)

def deploy(contract, evm_loader):
    with open(location_bin, mode='wb') as file:
        file.write(contract)

    cli = solana_cli(solana_url)
    output = cli.call("deploy --use-evm-loader {} {}".format(evm_loader, location_bin))
    print(type(output), output)
    return json.loads(output.splitlines()[-1])

def transaction_history(acc):
    cli = solana_cli(solana_url)
    output = cli.call("transaction-history {}".format(acc))
    return output.splitlines()[-2]

def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) != expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data

def getAccountInfo(client, eth_acc, evm_loader):
    (account_info, nonce) = create_program_address(bytes(eth_acc).hex(), evm_loader)
    data = _getAccountData(client, account_info, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(data)

def getLamports(client, evm_loader, eth_acc):
    (account, nonce) = create_program_address(bytes(eth_acc).hex(), evm_loader)
    return int(client.get_balance(account)['result']['value'])

