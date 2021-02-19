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

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
evm_loader_id = os.environ.get("EVM_LOADER", "BY8ZhLU2DiBvrvJZZYsH7TvCZJSgSmrvYtQzeomN2VGv")
sender_eth = "a6df389b014C45155086Ef10f365D9AF3Ab3D812"
location_bin = ".deploy_contract.bin"

tokenkeg = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
sysvarclock = "SysvarC1ock11111111111111111111111111111111"
system_id = '11111111111111111111111111111111'

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

