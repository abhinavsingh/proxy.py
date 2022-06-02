## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

from time import sleep
import unittest
import os
import json
from solana.rpc.commitment import Confirmed, Recent
from solana.rpc.types import TxOpts
from web3 import Web3
from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey
from solana.rpc.types import TokenAccountOpts

from ..testing.testing_helpers import request_airdrop
from ..common_neon.environment_data import EVM_LOADER_ID
from ..common_neon.erc20_wrapper import ERC20Wrapper
from ..common_neon.neon_instruction import NeonInstruction
from ..common_neon.compute_budget import TransactionWithComputeBudget

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/admin')
user = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/user')
proxy.eth.default_account = admin.address
request_airdrop(admin.address)
request_airdrop(user.address)

NAME = 'NEON'
SYMBOL = 'NEO'

class Test_erc20_wrapper_contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/197")
        print('admin.key:', admin.key.hex())
        print('admin.address:', admin.address)
        print('user.key:', user.key.hex())
        print('user.address:', user.address)

        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.create_token_accounts(cls)


    def create_token_mint(self):
        self.solana_client = SolanaClient(solana_url)

        with open("proxy/operator-keypairs/id.json") as f:
            d = json.load(f)
        self.solana_account = SolanaAccount(d[0:32])
        self.solana_client.request_airdrop(self.solana_account.public_key(), 1000_000_000_000, Confirmed)

        while True:
            balance = self.solana_client.get_balance(self.solana_account.public_key(), Confirmed)["result"]["value"]
            if balance > 0:
                break
            sleep(1)
        print('create_token_mint mint, SolanaAccount: ', self.solana_account.public_key())

        self.token = SplToken.create_mint(
            self.solana_client,
            self.solana_account,
            self.solana_account.public_key(),
            9,
            TOKEN_PROGRAM_ID,
        )

    def deploy_erc20_wrapper_contract(self):
        self.wrapper = ERC20Wrapper(proxy, NAME, SYMBOL,
                                    self.token, admin,
                                    self.solana_account,
                                    PublicKey(EVM_LOADER_ID))
        self.wrapper.deploy_wrapper()

    def create_token_accounts(self):
        admin_token_key = self.wrapper.get_neon_erc20_account_address(admin.address)

        admin_token_info = { "key": admin_token_key,
                             "owner": self.wrapper.get_neon_account_address(admin.address),
                             "contract": self.wrapper.solana_contract_address,
                             "mint": self.token.pubkey }

        tx = TransactionWithComputeBudget()
        ix = NeonInstruction(self.solana_account.public_key()).make_erc20token_account_instruction(admin_token_info)
        tx.add(ix)
        self.solana_client.send_transaction(tx, self.solana_account, opts=TxOpts(skip_preflight=True, skip_confirmation=False))
        self.wrapper.mint_to(admin_token_key, 10_000_000_000_000)

    def test_erc20_name(self):
        erc20 = proxy.eth.contract(address=self.wrapper.neon_contract_address, abi=self.wrapper.wrapper['abi'])
        name = erc20.functions.name().call()
        self.assertEqual(name, NAME)

    def test_erc20_symbol(self):
        erc20 = proxy.eth.contract(address=self.wrapper.neon_contract_address, abi=self.wrapper.wrapper['abi'])
        sym = erc20.functions.symbol().call()
        self.assertEqual(sym, SYMBOL)

    def test_erc20_decimals(self):
        erc20 = self.wrapper.erc20_interface()
        decs = erc20.functions.decimals().call()
        self.assertEqual(decs, 9)

    def test_erc20_totalSupply(self):
        erc20 = self.wrapper.erc20_interface()
        ts = erc20.functions.totalSupply().call()
        self.assertGreater(ts, 0)

    def test_erc20_balanceOf(self):
        erc20 = self.wrapper.erc20_interface()
        b = erc20.functions.balanceOf(admin.address).call()
        self.assertGreater(b, 0)
        b = erc20.functions.balanceOf(user.address).call()
        self.assertEqual(b, 0)

    def test_erc20_transfer(self):
        transfer_value = 1000
        erc20 = self.wrapper.erc20_interface()

        admin_balance_before = erc20.functions.balanceOf(admin.address).call()
        user_balance_before = erc20.functions.balanceOf(user.address).call()

        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx = erc20.functions.transfer(user.address, transfer_value).buildTransaction(tx)
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        admin_balance_after = erc20.functions.balanceOf(admin.address).call()
        user_balance_after = erc20.functions.balanceOf(user.address).call()

        self.assertEqual(admin_balance_after, admin_balance_before - transfer_value)
        self.assertEqual(user_balance_after, user_balance_before + transfer_value)

    def test_erc20_transfer_not_enough_funds(self):
        transfer_value = 100_000_000_000_000
        erc20 = self.wrapper.erc20_interface()

        admin_balance_before = erc20.functions.balanceOf(admin.address).call()
        user_balance_before = erc20.functions.balanceOf(user.address).call()

        with self.assertRaisesRegex(Exception, "ERC20 transfer failed"):
            erc20.functions.transfer(user.address, transfer_value).buildTransaction()

        admin_balance_after = erc20.functions.balanceOf(admin.address).call()
        user_balance_after = erc20.functions.balanceOf(user.address).call()

        self.assertEqual(admin_balance_after, admin_balance_before)
        self.assertEqual(user_balance_after, user_balance_before)

    def test_erc20_transfer_out_of_bounds(self):
        transfer_value = 0xFFFF_FFFF_FFFF_FFFF + 1
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20 transfer failed"):
            erc20.functions.transfer(user.address, transfer_value).buildTransaction()

    def test_erc20_approve(self):
        approve_value = 1000
        erc20 = self.wrapper.erc20_interface()

        allowance_before = erc20.functions.allowance(admin.address, user.address).call()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approve(user.address, approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertEqual(tx_receipt.status, 1)

        self.assertIsNotNone(tx_receipt)

        allowance_after = erc20.functions.allowance(admin.address, user.address).call()
        self.assertEqual(allowance_after, allowance_before + approve_value)

    def test_erc20_transferFrom(self):
        approve_value = 1000
        transfer_value = 100
        erc20 = self.wrapper.erc20_interface()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approve(user.address, approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        allowance_before = erc20.functions.allowance(admin.address, user.address).call()
        admin_balance_before = erc20.functions.balanceOf(admin.address).call()
        user_balance_before = erc20.functions.balanceOf(user.address).call()

        nonce = proxy.eth.get_transaction_count(user.address)
        tx = erc20.functions.transferFrom(admin.address, user.address, transfer_value).buildTransaction(
            {'nonce': nonce, 'from': user.address}
        )
        tx = proxy.eth.account.sign_transaction(tx, user.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        allowance_after = erc20.functions.allowance(admin.address, user.address).call()
        admin_balance_after = erc20.functions.balanceOf(admin.address).call()
        user_balance_after = erc20.functions.balanceOf(user.address).call()

        self.assertEqual(allowance_after, allowance_before - transfer_value)
        self.assertEqual(admin_balance_after, admin_balance_before - transfer_value)
        self.assertEqual(user_balance_after, user_balance_before + transfer_value)

    def test_erc20_transferFrom_beyond_approve(self):
        transfer_value = 10_000_000
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20 transferFrom failed"):
            erc20.functions.transferFrom(admin.address, user.address, transfer_value).buildTransaction(
                {'from': user.address}
            )

    def test_erc20_transferFrom_out_of_bounds(self):
        transfer_value = 0xFFFF_FFFF_FFFF_FFFF + 1
        erc20 = self.wrapper.erc20_interface()

        with self.assertRaisesRegex(Exception, "ERC20 transferFrom failed"):
            erc20.functions.transferFrom(admin.address, user.address, transfer_value).buildTransaction(
                {'from': user.address}
            )

    def test_erc20_approveSolana(self):
        delegate = SolanaAccount()
        approve_value = 1000
        erc20 = self.wrapper.erc20_interface()

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.approveSolana(bytes(delegate.public_key()), approve_value).buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertEqual(tx_receipt.status, 1)

        self.assertIsNotNone(tx_receipt)
        accounts = self.solana_client.get_token_accounts_by_delegate(delegate.public_key(), TokenAccountOpts(mint=self.token.pubkey), commitment=Recent)
        accounts = list(map(lambda a: PublicKey(a['pubkey']), accounts['result']['value']))

        self.assertIn(self.wrapper.get_neon_erc20_account_address(admin.address), accounts)


if __name__ == '__main__':
    unittest.main()
