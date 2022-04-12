import unittest
from solcx import compile_source
from web3 import Web3
import os
from .testing_helpers import request_airdrop
from solana.account import Account as SolanaAccount
from solana.rpc.api import Client as SolanaClient
from solana.rpc.types import TxOpts
from spl.token.client import Token as SplToken
from spl.token.instructions import get_associated_token_address, create_associated_token_account
from proxy.environment import NEON_TOKEN_MINT
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.commitment import Confirmed
from web3 import exceptions as web3_exceptions
from random import uniform
from eth_account.signers.local import LocalAccount as NeonAccount
from proxy.common_neon.compute_budget import TransactionWithComputeBudget

NEON_TOKEN_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract NeonToken {
    address constant NeonPrecompiled = 0xFF00000000000000000000000000000000000003;

    function withdraw(bytes32 spender) public payable {
        (bool success, bytes memory returnData) = NeonPrecompiled.delegatecall(abi.encodeWithSignature("withdraw(bytes32)", spender));
        require(success);
    }
}
'''


PROXY_URL = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
SOLANA_URL = os.environ.get('SOLANA_URL', 'http://solana:8899/')
proxy = Web3(Web3.HTTPProvider(PROXY_URL))
solana = SolanaClient(SOLANA_URL)

class TestNeonToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sol_payer = SolanaAccount()
        cls.deploy_contract(cls)
        cls.spl_neon_token = SplToken(solana, NEON_TOKEN_MINT, TOKEN_PROGRAM_ID, cls.sol_payer)

    def create_eth_account(self, balance):
        seed = f'TestAccount{uniform(0, 10000)}'
        new_neon_acc = proxy.eth.account.create(seed)
        request_airdrop(new_neon_acc.address, balance)
        print(f"New Neon account {new_neon_acc.address} with balance {balance}")
        return new_neon_acc

    def create_sol_account(self, balance = 1000_000_000_000):
        new_sol_acc = SolanaAccount()
        print(f"New Solana account {new_sol_acc.public_key()} with balance {balance}")
        solana.request_airdrop(new_sol_acc.public_key(), balance)
        return new_sol_acc

    def deploy_contract(self):
        artifacts = compile_source(NEON_TOKEN_CONTRACT)
        _, self.neon_token_iface = artifacts.popitem()

        self.neon_contract = proxy.eth.contract(abi=self.neon_token_iface['abi'],
                                                bytecode=self.neon_token_iface['bin'])

        deployer = self.create_eth_account(self, 100)
        proxy.eth.default_account = deployer.address

        nonce = proxy.eth.get_transaction_count(deployer.address)
        tx = {'nonce': nonce}
        tx_constructor = self.neon_contract.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, deployer.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        print(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print(f'tx_deploy_receipt: {tx_deploy_receipt}')
        print(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_token_address = tx_deploy_receipt.contractAddress
        print(f'NeonToken contract address is: {self.neon_token_address}')
        self.neon_contract = proxy.eth.contract(address=self.neon_token_address,
                                                abi=self.neon_token_iface['abi'])

    def withdraw(self, source_acc: NeonAccount, dest_acc: SolanaAccount, withdraw_amount_alan: int):
        nonce = proxy.eth.get_transaction_count(source_acc.address)
        tx = {'value': withdraw_amount_alan, 'nonce': nonce}
        withdraw_tx_dict = self.neon_contract.functions.withdraw(bytes(dest_acc.public_key())).buildTransaction(tx)
        withdraw_tx = proxy.eth.account.sign_transaction(withdraw_tx_dict, source_acc.key)
        withdraw_tx_hash = proxy.eth.send_raw_transaction(withdraw_tx.rawTransaction)
        print(f'withdraw_tx_hash: {withdraw_tx_hash.hex()}')
        withdraw_tx_receipt = proxy.eth.wait_for_transaction_receipt(withdraw_tx_hash)
        print(f'withdraw_tx_receipt: {withdraw_tx_receipt}')
        print(f'deploy status: {withdraw_tx_receipt.status}')

    def test_success_withdraw_to_non_existing_account(self):
        """
        Should succesfully withdraw NEON tokens to previously non-existing Associated Token Account
        """
        source_acc = self.create_eth_account(10)
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.public_key(), NEON_TOKEN_MINT)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = pow(10, 18) # 1 NEON
        withdraw_amount_galan = int(withdraw_amount_alan / 1_000_000_000)

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(destination_balance_before_galan['error'] is not None)

        self.withdraw(source_acc, dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertLess(source_balance_after_alan, source_balance_before_alan - withdraw_amount_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertEqual(int(destination_balance_after_galan['result']['value']['amount']), withdraw_amount_galan)

    def test_success_withdraw_to_existing_account(self):
        """
        Should succesfully withdraw NEON tokens to existing Associated Token Account
        """
        source_acc = self.create_eth_account(10)
        dest_acc = self.create_sol_account()

        # Creating destination Associated Token Account
        trx = TransactionWithComputeBudget()
        trx.add(
            create_associated_token_account(
                dest_acc.public_key(),
                dest_acc.public_key(),
                NEON_TOKEN_MINT
            )
        )
        opts = TxOpts(skip_preflight=True, skip_confirmation=False)
        solana.send_transaction(trx, dest_acc, opts=opts)

        dest_token_acc = get_associated_token_address(dest_acc.public_key(), NEON_TOKEN_MINT)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = 2_123_000_321_000_000_000
        withdraw_amount_galan = int(withdraw_amount_alan / 1_000_000_000)

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must exist with zero balance)
        resp = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        destination_balance_before_galan = int(resp['result']['value']['amount'])
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertEqual(destination_balance_before_galan, 0)

        self.withdraw(source_acc, dest_acc, withdraw_amount_alan)

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertLess(source_balance_after_alan, source_balance_before_alan - withdraw_amount_alan)

        # Check destination balance
        resp = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        destination_balance_after_galan = int(resp['result']['value']['amount'])
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertEqual(destination_balance_after_galan, withdraw_amount_galan)

    def test_failed_withdraw_non_divisible_amount(self):
        """
        Should fail withdrawal because amount not divised by 1 billion
        """
        source_acc = self.create_eth_account(10)
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.public_key(), NEON_TOKEN_MINT)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = pow(10, 18) + 123 # NEONs

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(destination_balance_before_galan['error'] is not None)

        with self.assertRaises(web3_exceptions.ContractLogicError) as er:
            self.withdraw(source_acc, dest_acc, withdraw_amount_alan)
        print(f'Exception occured: {er.exception}')

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(destination_balance_after_galan['error'] is not None)

    def test_failed_withdraw_insufficient_balance(self):
        """
        Should fail withdrawal because of insufficient balance
        """
        source_acc = self.create_eth_account(1)
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.public_key(), NEON_TOKEN_MINT)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = 2 * pow(10, 18) # 2 NEONs

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(destination_balance_before_galan['error'] is not None)

        with self.assertRaises(ValueError) as er:
            self.withdraw(source_acc, dest_acc, withdraw_amount_alan)
        print(f'Exception occured: {er.exception}')

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(destination_balance_after_galan['error'] is not None)

    def test_failed_withdraw_all_balance(self):
        """
        Should fail withdrawal all balance
        """
        source_acc = self.create_eth_account(1) # 1 NEON
        dest_acc = self.create_sol_account()

        dest_token_acc = get_associated_token_address(dest_acc.public_key(), NEON_TOKEN_MINT)
        print(f"Destination token account: {dest_token_acc}")

        withdraw_amount_alan = 1_000_000_000_000_000_000 # 1 NEON

        # Check source balance
        source_balance_before_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance before (Alan): {source_balance_before_alan}')

        # Check destination balance (must not exist)
        destination_balance_before_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance before (Galan): {destination_balance_before_galan}')
        self.assertTrue(destination_balance_before_galan['error'] is not None)

        with self.assertRaises(ValueError) as er:
            self.withdraw(source_acc, dest_acc, withdraw_amount_alan)
        print(f'Exception occured: {er.exception}')

        # Check source balance
        source_balance_after_alan = proxy.eth.get_balance(source_acc.address)
        print(f'Source account balance after (Alan): {source_balance_after_alan}')
        self.assertEqual(source_balance_after_alan, source_balance_before_alan)

        # Check destination balance
        destination_balance_after_galan = self.spl_neon_token.get_balance(dest_token_acc, commitment=Confirmed)
        print(f'Destination account balance after (Galan): {destination_balance_after_galan}')
        self.assertTrue(destination_balance_after_galan['error'] is not None)
