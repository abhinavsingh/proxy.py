import os

from proxy.common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY
from proxy.environment import ETH_TOKEN_MINT_ID, MINIMAL_GAS_PRICE

os.environ['SOLANA_URL'] = "http://solana:8899"
os.environ['EVM_LOADER'] = "53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io"
os.environ['ETH_TOKEN_MINT'] = "HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU"
os.environ['COLLATERAL_POOL_BASE'] = "4sW3SZDJB7qXUyCYKA7pFL8eCTfm3REr8oSiKkww7MaT"

import base64
import datetime
import multiprocessing
import unittest
import rlp
from eth_tx_utils import make_instruction_data_from_tx, make_keccak_instruction_data
from eth_utils import big_endian_to_int
from ethereum.transactions import Transaction as EthTrx
from ethereum.utils import sha3
from solana.publickey import PublicKey
from solana.rpc.commitment import Confirmed
from solana.system_program import SYS_PROGRAM_ID
from solana.transaction import AccountMeta, Transaction, TransactionInstruction
from solana_utils import *
from solcx import install_solc
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from web3 import Web3
from web3.auto.gethdev import w3

install_solc(version='0.7.0')
from solcx import compile_source

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/365'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create(SEED)
proxy.eth.default_account = eth_account.address

ACCOUNT_SEED_VERSION=b'\1'


TEST_RETRY_BLOCKED_365 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract BlockForAWhile {
    uint32 counter = 0;

    function add_some(uint32 some, uint32 loop, string memory _padding) public {
        for(uint32 i = 0; i < loop; i++){
            counter += some + i;
        }
    }
}
'''


def send_routine(acc_seed, contractAddress, abi, loop, return_dict, padding_string):
    print("Send parallel transaction from {}".format(acc_seed))
    print(datetime.datetime.now().time())
    storage_contract = proxy.eth.contract(
            address=contractAddress,
            abi=abi
        )
    new_eth_account = proxy.eth.account.create(acc_seed)
    right_nonce = proxy.eth.get_transaction_count(new_eth_account.address)
    trx_store = storage_contract.functions.add_some(2, loop, padding_string).buildTransaction(
        {
            "chainId": proxy.eth.chain_id,
            "gas": 987654321,
            "gasPrice": 0,
            "nonce": right_nonce,
        }
    )
    trx_store_signed = proxy.eth.account.sign_transaction(trx_store, new_eth_account.key)
    trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
    trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)
    return_dict[acc_seed] = trx_store_receipt


class BlockedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\ntest_retry_on_blocked_accounts.py setUpClass")

        cls.token = SplToken(solana_url)
        wallet = WalletAccount(wallet_path())
        cls.loader = EvmLoader(wallet, EVM_LOADER)
        cls.acc = wallet.get_acc()

        cls.deploy_contract(cls)

        print(cls.storage_contract.address)

        cls.reId_eth = cls.storage_contract.address.lower()
        print ('contract_eth', cls.reId_eth)
        (cls.reId, cls.reId_token, cls.re_code) = cls.get_accounts(cls, cls.reId_eth)
        print ('contract', cls.reId)
        print ('contract_code', cls.re_code)

        proxy.eth.default_account
        # Create ethereum account for user account
        cls.caller_ether = proxy.eth.default_account.lower()
        (cls.caller, cls.caller_token, _) = cls.get_accounts(cls, cls.caller_ether)
        print ('caller_ether', cls.caller_ether)
        print ('caller', cls.caller)

        if getBalance(cls.caller) == 0:
            print("Create caller account...")
            _ = cls.loader.createEtherAccount(cls.caller_ether)
            print("Done\n")
        # cls.token.transfer(ETH_TOKEN_MINT_ID, 2000, cls.caller_token)

        collateral_pool_index = 2
        cls.collateral_pool_address = create_collateral_pool_address(collateral_pool_index)
        cls.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')

    def get_accounts(self, ether):
        (sol_address, _) = self.loader.ether2program(ether)
        info = client.get_account_info(sol_address, commitment=Confirmed)['result']['value']
        data = base64.b64decode(info['data'][0])
        acc_info = ACCOUNT_INFO_LAYOUT.parse(data)

        code_address = PublicKey(acc_info.code_account)
        alternate_token = get_associated_token_address(PublicKey(sol_address), ETH_TOKEN_MINT_ID)

        return (sol_address, alternate_token, code_address)

    def deploy_contract(self):
        compiled_sol = compile_source(TEST_RETRY_BLOCKED_365)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=storage.bytecode),
            eth_account.key
        )
        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.contractAddress = trx_deploy_receipt.contractAddress
        self.abi = storage.abi

        self.storage_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=storage.abi
        )

    def create_blocked_transaction(self):
        print("\ncreate_blocked_transaction")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.add_some(1, 30, "").buildTransaction({'nonce': right_nonce, 'gasPrice': MINIMAL_GAS_PRICE})
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)

        (from_addr, sign, msg) = make_instruction_data_from_tx(trx_store_signed.rawTransaction.hex())
        instruction = from_addr + sign + msg

        (_trx_raw, self.tx_hash, from_address) = self.get_trx_receipts(msg, sign)
        print(self.tx_hash)
        print(from_address)

        self.storage = self.create_storage_account(sign[:8].hex())
        print("storage", self.storage)
        self.combined_trx = self.make_combined_transaction(self.storage, 500, msg, instruction)
        return send_transaction(client, self.combined_trx, self.acc)

    def finish_blocker_transaction(self):
        while True:
            try:
                send_transaction(client, self.combined_trx, self.acc)
            except:
                break

    def get_trx_receipts(self, unsigned_msg, signature):
        trx = rlp.decode(unsigned_msg, EthTrx)

        v = int(signature[64]) + 35 + 2 * trx[6]
        r = big_endian_to_int(signature[0:32])
        s = big_endian_to_int(signature[32:64])

        trx_raw = rlp.encode(EthTrx(trx[0], trx[1], trx[2], trx[3], trx[4], trx[5], v, r, s), EthTrx)
        eth_signature = '0x' + sha3(trx_raw).hex()
        from_address = w3.eth.account.recover_transaction(trx_raw).lower()

        return (trx_raw.hex(), eth_signature, from_address)


    def sol_instr_partial_call_or_continue(self, storage_account, step_count, evm_instruction):
        return TransactionInstruction(
            program_id=self.loader.loader_id,
            data=bytearray.fromhex("0D") + self.collateral_pool_index_buf + step_count.to_bytes(8, byteorder='little') + evm_instruction,
            keys=[
                AccountMeta(pubkey=storage_account, is_signer=False, is_writable=True),

                # System instructions account:
                AccountMeta(pubkey=PublicKey(SYSVAR_INSTRUCTION_PUBKEY), is_signer=False, is_writable=False),
                # Operator address:
                AccountMeta(pubkey=self.acc.public_key(), is_signer=True, is_writable=True),
                # Collateral pool address:
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                # Operator's NEON token account:
                AccountMeta(pubkey=get_associated_token_address(self.acc.public_key(), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
                # User's NEON token account:
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                # System program account:
                AccountMeta(pubkey=PublicKey(SYS_PROGRAM_ID), is_signer=False, is_writable=False),

                AccountMeta(pubkey=self.reId, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.re_code, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),

                AccountMeta(pubkey=self.loader.loader_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
            ])


    def sol_instr_keccak(self, keccak_instruction):
        return TransactionInstruction(program_id=keccakprog, data=keccak_instruction, keys=[
                AccountMeta(pubkey=PublicKey(keccakprog), is_signer=False, is_writable=False), ])


    def make_combined_transaction(self, storage, steps, msg, instruction):
        print("make_combined_transaction")
        trx = Transaction()
        trx.add(self.sol_instr_keccak(make_keccak_instruction_data(1, len(msg), 13)))
        trx.add(self.sol_instr_partial_call_or_continue(storage, steps, instruction))
        print(trx.__dict__)
        return trx


    def create_storage_account(self, seed):
        storage = PublicKey(sha256(bytes(self.acc.public_key()) + bytes(seed, 'utf8') + bytes(PublicKey(EVM_LOADER))).digest())
        print("Storage", storage)

        if getBalance(storage) == 0:
            trx = Transaction()
            trx.add(createAccountWithSeed(self.acc.public_key(), self.acc.public_key(), seed, 10**9, 128*1024, PublicKey(EVM_LOADER)))
            send_transaction(client, trx, self.acc)

        return storage

    def test_blocked_iterative(self):
        print("\ntest_blocked_iterative")
        self.create_blocked_transaction()
        caller_seed = "long"
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        p2 = multiprocessing.Process(target=send_routine, args=(caller_seed, self.contractAddress, self.abi, 50, return_dict,
        """
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
        """))
        p2.start()
        self.finish_blocker_transaction()
        p2.join()
        print('return_dict:', return_dict)
        self.assertEqual(return_dict[caller_seed]['status'], 1)

    def test_blocked_single(self):
        print("\ntest_blocked_single")
        self.create_blocked_transaction()
        caller_seed = "short"
        manager = multiprocessing.Manager()
        return_dict = manager.dict()
        p2 = multiprocessing.Process(target=send_routine, args=(caller_seed, self.contractAddress, self.abi, 10, return_dict, ""))
        p2.start()
        self.finish_blocker_transaction()
        p2.join()
        print('return_dict:', return_dict)
        self.assertEqual(return_dict[caller_seed]['status'], 1)



if __name__ == '__main__':
    unittest.main()
