from solana.rpc.api import Client
from solana.account import Account
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

evm_loader_id = os.environ.get("EVM_LOADER", "3EvDG5aTfN4csM57WjxymnovHpyojZQExM6HZ9FmCgve")
erc20_id = os.environ.get("ERC20", "FRp8E7Bj9tPuPX57ynD7WtZAKkFqQzk3WPEyXA6Rg613")
sender_eth = "cf9f430be7e6c473ec1556004650328c71051bd4"
tokenkeg = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
sysvarclock = "SysvarC1ock11111111111111111111111111111111"

system_id = '11111111111111111111111111111111'
solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
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

def create_program_address(ether):
    cli = solana_cli(solana_url)
    output = cli.call("create-program-address {} {}".format(ether.hex(), evm_loader_id))
    items = output.rstrip().split('  ')
    return (items[0], int(items[1]))

class ERC20_Program():
    def __init__(self, client, signer):
        self.acc = signer
        self.client = client
        self.evm_loader = evm_loader_id
        self.program = erc20_id
        self.caller_ether = bytes.fromhex(sender_eth)
        (self.caller, self.caller_nonce) = create_program_address(self.caller_ether)
        self.balance = self.erc20_balance_ext()
        self.mint_id = self.erc20_mint_id()

    def erc20_balance_ext(self):
        input = bytearray.fromhex("0340b6674d")
        trx = Transaction().add(
            TransactionInstruction(program_id=self.evm_loader, data=input, keys=
            [
                AccountMeta(pubkey=self.program, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.acc.public_key(), is_signer=True, is_writable=False),
                AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
            ]))

        result = self.client.send_transaction(trx, self.acc)
        result = confirm_transaction(self.client, result["result"])
        messages = result["result"]["meta"]["logMessages"]
        res = messages[messages.index("Program log: succeed") + 1]
        if not res.startswith("Program log: "):
            raise Exception("Invalid program logs: no result")
        else:
            return res[13:]

    def erc20_mint_id(self):
        input = bytearray.fromhex("03e132a122")
        trx = Transaction().add(
            TransactionInstruction(program_id=self.evm_loader, data=input, keys=
            [
                AccountMeta(pubkey=self.program, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.acc.public_key(), is_signer=True, is_writable=False),
                AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
            ]))

        result = self.client.send_transaction(trx, self.acc)
        result = confirm_transaction(self.client, result["result"])
        messages = result["result"]["meta"]["logMessages"]
        res = messages[messages.index("Program log: succeed") + 1]
        if not res.startswith("Program log: "):
            raise Exception("Invalid program logs: no result")
        else:
            return res[13:]

    def erc20_transfer(self, eth_to, amount):
        input = bytearray.fromhex(
            "03a9059cbb" +
            str("%024x" % 0) + bytes(eth_to).hex() +
            "%064x" % amount
        )
        trx = Transaction().add(
            TransactionInstruction(program_id=self.evm_loader, data=input, keys=
            [
                AccountMeta(pubkey=self.program, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.acc.public_key(), is_signer=True, is_writable=False),
                AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
            ]))

        result = self.client.send_transaction(trx, self.acc)
        result = confirm_transaction(self.client, result["result"])
        messages = result["result"]["meta"]["logMessages"]
        res = messages[messages.index("Program log: succeed") + 1]
        if not res.startswith("Program log: "):
            raise Exception("Invalid program logs: no result")
        else:
            res = int(res[13:], 16)
            if not  (res == 1) :
                raise Exception("Invalid ERC20 transaction result: ", res)
            return result["result"]["transaction"]["signatures"][0]

    def erc20_balance(self, ether_acc):
        input = bytearray.fromhex(
            "0370a08231" +
            str("%024x" % 0) + bytes(ether_acc).hex()
        )
        trx = Transaction().add(
            TransactionInstruction(program_id=self.evm_loader, data=input, keys=
            [
                AccountMeta(pubkey=self.program, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.acc.public_key(), is_signer=True, is_writable=False),
                AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
            ]))

        result = self.client.send_transaction(trx, self.acc)
        result = confirm_transaction(self.client, result["result"])
        messages = result["result"]["meta"]["logMessages"]
        res = messages[messages.index("Program log: succeed") + 1]
        if not res.startswith("Program log: "):
            raise Exception("Invalid program logs: no result")
        else:
            return int(res[13:], 16)

    def getBalanceInfo(self, eth_token, eth_acc):
        mint = solana2ether(self.mint_id)
        if (mint.hex() != str(eth_token)[2:]):
            raise Exception("token_id doesn't match:  {},  erc20: ".format(eth_token, mint.hex()))
        balance = self.erc20_balance(eth_acc)
        return balance

    def transfer(self, eth_token, eth_payer, eth_to_acc, amount):
        mint = solana2ether(self.mint_id)
        if (mint.hex() != str(eth_token)[2:]):
            raise Exception("token_id doesn't match:  {},  erc20 {}: ".format(eth_token, mint.hex()))
        if (self.caller_ether.hex() != bytes(eth_payer).hex() ):
            print ("msg.sender, payer: {} {}".format(self.caller_ether.hex(), bytes(eth_payer).hex()))
            raise Exception("msg.sender does not match the payer's account")
        signature = self.erc20_transfer(eth_to_acc, amount)
        print("erc20 transfer to {}: {}".format(str(eth_to_acc), signature))
        return signature

