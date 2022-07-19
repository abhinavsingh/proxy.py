import json
import os
import time

os.environ['SOLANA_URL'] = "http://solana:8899"
os.environ['EVM_LOADER'] = "53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io"
os.environ['ETH_TOKEN_MINT'] = "HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU"
os.environ['COLLATERAL_POOL_BASE'] = "4sW3SZDJB7qXUyCYKA7pFL8eCTfm3REr8oSiKkww7MaT"

import base64
import unittest

import rlp
from .eth_tx_utils import (make_instruction_data_from_tx,
                          make_keccak_instruction_data)
from eth_utils import big_endian_to_int
from ethereum.transactions import Transaction as EthTrx
from ethereum.utils import sha3
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.system_program import SYS_PROGRAM_ID
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from .solana_utils import *
from solcx import compile_source
from web3 import Web3
from web3.auto.gethdev import w3

from ..common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.address import EthereumAddress
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.neon_instruction import NeonInstruction
from ..common_neon.eth_proto import Trx

from .testing_helpers import request_airdrop

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
proxy_program = os.environ.get("TEST_PROGRAM")

MINIMAL_GAS_PRICE = 1
SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/196'
SEED_INVOKED = 'https://github.com/neonlabsorg/proxy-model.py/issues/755'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create(SEED)
eth_account_invoked = proxy.eth.account.create(SEED_INVOKED)
eth_account_getter = proxy.eth.account.create("GETTER")
proxy.eth.default_account = eth_account.address

ACCOUNT_SEED_VERSION=b'\1'

TEST_EVENT_SOURCE_196 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract ReturnsEvents {
    event Added(uint8 sum);

    function addNoReturn(uint8 x, uint8 y) public {
        x + y;
    }

    function addReturn(uint8 x, uint8 y) public returns(uint8) {
        return x + y;
    }

    function addReturnEvent(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum =x+y;

        emit Added(sum);
        return sum;
    }

    function addReturnEventTwice(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum = x + y;
        emit Added(sum);
        sum += y;
        emit Added(sum);
        return sum;
    }
}
'''


class CancelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\ntest_indexer_work.py setUpClass")

        request_airdrop(eth_account.address)
        request_airdrop(eth_account_invoked.address)
        request_airdrop(eth_account_getter.address)

        print(f"proxy_program: {proxy_program}")

        wallet = WalletAccount(wallet_path())
        cls.loader = EvmLoader(wallet, EVM_LOADER)
        cls.acc = wallet.get_acc()

        cls.deploy_contract(cls)

        print(cls.storage_contract.address)

        cls.reId_eth = cls.storage_contract.address.lower()
        print ('contract_eth', cls.reId_eth)
        (cls.reId, cls.re_code) = cls.get_accounts(cls, cls.reId_eth)
        print ('contract', cls.reId)
        print ('contract_code', cls.re_code)

        # Create ethereum account for user account
        cls.caller_ether = EthereumAddress.from_private_key(bytes(eth_account.key))
        (cls.caller, _) = cls.get_accounts(cls, cls.caller_ether)
        cls.caller_ether_invoked = EthereumAddress.from_private_key(bytes(eth_account_invoked.key))
        (cls.caller_invoked, _) = cls.get_accounts(cls, cls.caller_ether_invoked)
        cls.caller_ether_getter = EthereumAddress.from_private_key(bytes(eth_account_getter.key))
        (cls.caller_getter, _) = cls.get_accounts(cls, cls.caller_ether_getter)
        print (f'caller_ether: {cls.caller_ether} {cls.caller}')
        print (f'caller_ether_invoked: {cls.caller_ether_invoked} {cls.caller_invoked}')
        print (f'caller_ether_getter: {cls.caller_ether_getter} {cls.caller_getter}')

        if getBalance(cls.caller) == 0:
            print("Create caller account...")
            _ = cls.loader.createEtherAccount(cls.caller_ether)
            print("Done\n")
        # cls.token.transfer(NEON_TOKEN_MINT, 2000, cls.caller_token)

        collateral_pool_index = 2
        cls.collateral_pool_address = create_collateral_pool_address(collateral_pool_index)
        cls.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')

        cls.create_hanged_transaction(cls)
        cls.create_invoked_transaction(cls)
        cls.create_invoked_transaction_combined(cls)
        cls.create_two_calls_in_transaction(cls)

    def get_accounts(self, ether):
        (sol_address, _) = self.loader.ether2program(str(ether))
        info = client.get_account_info(sol_address, commitment=Confirmed)['result']['value']
        data = base64.b64decode(info['data'][0])
        acc_info = ACCOUNT_INFO_LAYOUT.parse(data)

        code_address = PublicKey(acc_info.code_account)

        return (sol_address, code_address)

    def deploy_contract(self):
        compiled_sol = compile_source(TEST_EVENT_SOURCE_196)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to='',
            value=0,
            data=storage.bytecode),
            eth_account.key
        )
        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.storage_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=storage.abi,
            bytecode=contract_interface['bin']
        )

    def create_hanged_transaction(self):
        print("\ncreate_hanged_transaction")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.addReturnEventTwice(1, 1).buildTransaction({'nonce': right_nonce, 'gasPrice': MINIMAL_GAS_PRICE})
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)

        (from_addr, sign, msg) = make_instruction_data_from_tx(trx_store_signed.rawTransaction.hex())
        instruction = from_addr + sign + msg

        (trx_raw, self.tx_hash, from_address) = self.get_trx_receipts(self, msg, sign)
        print(self.tx_hash)
        print(from_address)

        self.storage = self.create_storage_account(self, sign[:8].hex())
        print("storage", self.storage)
        self.call_begin(self, self.storage, 10, msg, instruction)

    def create_invoked_transaction(self):
        print("\ncreate_invoked_transaction")

        trx_transfer_signed = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account_invoked.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to=eth_account_getter.address,
            value=1_000_000_000_000_000_000),
            eth_account_invoked.key
        )

        (from_addr, sign, msg) = make_instruction_data_from_tx(trx_transfer_signed.rawTransaction.hex())

        (trx_raw, self.tx_hash_invoked, from_address) = self.get_trx_receipts(self, msg, sign)
        print(self.tx_hash_invoked)
        print(from_address)

        eth_meta_list = [
            AccountMeta(pubkey=self.caller_getter, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.caller_invoked, is_signer=False, is_writable=True),
        ]
        eth_tx = Trx.fromString(bytearray.fromhex(trx_transfer_signed.rawTransaction.hex()[2:]))

        tx = TransactionWithComputeBudget()
        builder = NeonInstruction(self.acc.public_key())
        builder.init_operator_ether(self.caller_ether)
        builder.init_eth_trx(eth_tx, eth_meta_list)
        noniterative_transaction = builder.make_noniterative_call_transaction(len(tx.instructions))

        # noniterative_transaction.instructions[-1].program_id = proxy_program
        noniterative_transaction.instructions[-1].keys.insert(0, AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False))
        noniterative_transaction.instructions[-1] = TransactionInstruction(
            keys=noniterative_transaction.instructions[-1].keys,
            data=noniterative_transaction.instructions[-1].data,
            program_id=proxy_program
        )

        tx.add(noniterative_transaction)

        print(tx.__dict__)

        SolanaClient(solana_url).send_transaction(tx, self.acc, opts=TxOpts(skip_preflight=False, skip_confirmation=False))

    def create_invoked_transaction_combined(self):
        print("\ncreate_invoked_transaction_combined")

        trx_transfer_signed = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account_invoked.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to=eth_account_getter.address,
            value=500_000_000_000_000_000),
            eth_account_invoked.key
        )

        (from_addr, sign, msg) = make_instruction_data_from_tx(trx_transfer_signed.rawTransaction.hex())

        (trx_raw, self.tx_hash_invoked_combined, from_address) = self.get_trx_receipts(self, msg, sign)
        print(self.tx_hash_invoked_combined)
        print(from_address)

        storage_for_invoked = self.create_storage_account(self, sign[:8].hex())
        time.sleep(10)

        eth_meta_list = [
            AccountMeta(pubkey=self.caller_getter, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.caller_invoked, is_signer=False, is_writable=True),
        ]
        eth_tx = Trx.fromString(bytearray.fromhex(trx_transfer_signed.rawTransaction.hex()[2:]))

        tx = TransactionWithComputeBudget()
        builder = NeonInstruction(self.acc.public_key())
        builder.init_operator_ether(self.caller_ether)
        builder.init_eth_trx(eth_tx, eth_meta_list)
        builder.init_iterative(storage_for_invoked, None, None)
        # builder.make_partial_call_or_continue_transaction(250, len(tx.instructions))

        keccak_instruction = builder.make_keccak_instruction(len(tx.instructions) + 1, len(eth_tx.unsigned_msg()), 14)
        iterative_transaction = builder.make_partial_call_or_continue_instruction(250)

        # noniterative_transaction.instructions[-1].program_id = proxy_program
        iterative_transaction.keys.insert(0, AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False))
        iterative_transaction = TransactionInstruction(
            keys=iterative_transaction.keys,
            data=bytearray.fromhex("ef") + iterative_transaction.data,
            program_id=proxy_program
        )

        tx.add(keccak_instruction)
        tx.add(iterative_transaction)

        print(tx.__dict__)

        SolanaClient(solana_url).send_transaction(tx, self.acc, opts=TxOpts(skip_preflight=False, skip_confirmation=False))

    def create_two_calls_in_transaction(self):
        print("\ncreate_two_calls_in_transaction")

        account_list = [
            AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.reId, is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.re_code, is_signer=False, is_writable=True),
        ]

        nonce1 = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce1, 'gasPrice': MINIMAL_GAS_PRICE}
        call1_dict = self.storage_contract.functions.addReturn(1, 1).buildTransaction(tx)
        call1_signed = proxy.eth.account.sign_transaction(call1_dict, eth_account.key)
        (from_addr, sign1, msg1) = make_instruction_data_from_tx(call1_signed.rawTransaction.hex())
        (raw, self.tx_hash_call1, from_addr) = self.get_trx_receipts(self, msg1, sign1)
        print('tx_hash_call1:', self.tx_hash_call1)

        nonce2 = nonce1 + 1
        tx = {'nonce': nonce2, 'gasPrice': MINIMAL_GAS_PRICE}
        call2_dict = self.storage_contract.functions.addReturnEvent(2, 2).buildTransaction(tx)
        call2_signed = proxy.eth.account.sign_transaction(call2_dict, eth_account.key)
        (from_addr, sign2, msg2) = make_instruction_data_from_tx(call2_signed.rawTransaction.hex())
        (raw, self.tx_hash_call2, from_addr) = self.get_trx_receipts(self, msg2, sign2)
        print('tx_hash_call2:', self.tx_hash_call2)

        tx = TransactionWithComputeBudget()

        call1_tx = Trx.fromString(bytearray.fromhex(call1_signed.rawTransaction.hex()[2:]))
        builder = NeonInstruction(self.acc.public_key())
        builder.init_operator_ether(self.caller_ether)
        builder.init_eth_trx(call1_tx, account_list)
        noniterative1 = builder.make_noniterative_call_transaction(len(tx.instructions))
        tx.add(noniterative1)

        call2_tx = Trx.fromString(bytearray.fromhex(call2_signed.rawTransaction.hex()[2:]))
        builder = NeonInstruction(self.acc.public_key())
        builder.init_operator_ether(self.caller_ether)
        builder.init_eth_trx(call2_tx, account_list)
        noniterative2 = builder.make_noniterative_call_transaction(len(tx.instructions))
        tx.add(noniterative2)

        #print(tx.__dict__)
        opts=TxOpts(skip_preflight=False, skip_confirmation=False, preflight_commitment=Confirmed)
        SolanaClient(solana_url).send_transaction(tx, self.acc, opts=opts)

    def get_trx_receipts(self, unsigned_msg, signature):
        trx = rlp.decode(unsigned_msg, EthTrx)

        v = int(signature[64]) + 35 + 2 * trx[6]
        r = big_endian_to_int(signature[0:32])
        s = big_endian_to_int(signature[32:64])

        trx_raw = rlp.encode(EthTrx(trx[0], trx[1], trx[2], trx[3], trx[4], trx[5], v, r, s), EthTrx)
        eth_signature = '0x' + sha3(trx_raw).hex()
        from_address = w3.eth.account.recover_transaction(trx_raw).lower()

        return (trx_raw.hex(), eth_signature, from_address)

    def sol_instr_19_partial_call(self, storage_account, step_count, evm_instruction):
        return TransactionInstruction(
            program_id=self.loader.loader_id,
            data=bytearray.fromhex("13") + self.collateral_pool_index_buf + step_count.to_bytes(8, byteorder='little') + evm_instruction,
            keys=[
                AccountMeta(pubkey=storage_account, is_signer=False, is_writable=True),

                # System instructions account:
                AccountMeta(pubkey=PublicKey(SYSVAR_INSTRUCTION_PUBKEY), is_signer=False, is_writable=False),
                # Operator address:
                AccountMeta(pubkey=self.acc.public_key(), is_signer=True, is_writable=True),
                # Collateral pool address:
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                # Operator's NEON token account: pay gas to caller
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                # System program account:
                AccountMeta(pubkey=PublicKey(SYS_PROGRAM_ID), is_signer=False, is_writable=False),
                # NeonEVM program account:
                AccountMeta(pubkey=self.loader.loader_id, is_signer=False, is_writable=False),

                AccountMeta(pubkey=self.reId, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.re_code, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
            ])

    def call_begin(self, storage, steps, msg, instruction):
        print("Begin")
        trx = TransactionWithComputeBudget()
        trx.add(self.sol_instr_keccak(self, make_keccak_instruction_data(len(trx.instructions) + 1, len(msg), 13)))
        trx.add(self.sol_instr_19_partial_call(self, storage, steps, instruction))
        print(trx.__dict__)
        SolanaClient(solana_url).send_transaction(trx, self.acc, opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def sol_instr_keccak(self, keccak_instruction):
        return TransactionInstruction(program_id=keccakprog, data=keccak_instruction, keys=[
                AccountMeta(pubkey=PublicKey(keccakprog), is_signer=False, is_writable=False), ])

    def create_storage_account(self, seed):
        storage = PublicKey(sha256(bytes(self.acc.public_key()) + bytes(seed, 'utf8') + bytes(PublicKey(EVM_LOADER))).digest())
        print("Storage", storage)

        if getBalance(storage) == 0:
            trx = TransactionWithComputeBudget()
            trx.add(createAccountWithSeed(self.acc.public_key(), self.acc.public_key(), seed, 10**9, 128*1024, PublicKey(EVM_LOADER)))
            SolanaClient(solana_url).send_transaction(trx, self.acc, opts=TxOpts(skip_preflight=True, skip_confirmation=False))

        return storage

    # @unittest.skip("a.i.")
    def test_01_canceled(self):
        print("\ntest_01_canceled")
        trx_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash)
        print('trx_receipt:', trx_receipt)
        self.assertEqual(trx_receipt['status'], 0)

    def test_02_get_code_from_indexer(self):
        print("\ntest_02_get_code_from_indexer")
        code = proxy.eth.get_code(self.storage_contract.address)
        self.assertEqual(code, self.storage_contract.bytecode[-len(code):])

    def test_03_invoked_found(self):
        print("\ntest_03_invoked_found")
        trx_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_invoked)
        print('trx_receipt:', trx_receipt)

    def test_04_right_result_for_invoked(self):
        print("\ntest_04_right_result_for_invoked")
        trx_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_invoked_combined)
        print('trx_receipt:', trx_receipt)

    def test_05_check_two_calls_in_transaction(self):
        print("\ntest_05_check_two_calls_in_transaction")
        call1_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_call1)
        print('test_05 receipt1:', call1_receipt)
        self.assertEqual(len(call1_receipt['logs']), 0)
        call2_receipt = proxy.eth.wait_for_transaction_receipt(self.tx_hash_call2)
        print('test_05 receipt2:', call2_receipt)
        self.assertEqual(len(call2_receipt['logs']), 1)


if __name__ == '__main__':
    unittest.main()
