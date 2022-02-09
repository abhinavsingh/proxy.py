## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

from time import sleep
import unittest
import os
import json
from xmlrpc.client import Boolean
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from web3 import Web3
from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey
from proxy.environment import EVM_LOADER_ID
from proxy.common_neon.erc20_wrapper import ERC20Wrapper
from proxy.common_neon.neon_instruction import NeonInstruction
from solcx import compile_source

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/admin')
proxy.eth.default_account = admin.address

CONTRACT = '''
pragma solidity >= 0.7.0;

contract ReadOnly {

    function balanceOf(address a) public view returns(uint256) {
        return a.balance;
    }
}
'''


class Test_read_only_accounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.deploy_test_contract(cls)

    def account_exists(self, key: PublicKey) -> Boolean:
        info = self.solana_client.get_account_info(key)
        info["result"]["value"] is not None

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
        self.wrapper = ERC20Wrapper(proxy, "NEON", "NEON",
                                    self.token, admin,
                                    self.solana_account,
                                    PublicKey(EVM_LOADER_ID))
        self.wrapper.deploy_wrapper()

    def deploy_test_contract(self):
        compiled = compile_source(CONTRACT)
        id, interface = compiled.popitem()
        contract = proxy.eth.contract(abi=interface['abi'], bytecode=interface['bin'])
        trx = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(admin.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=contract.bytecode),
            admin.key
        )
        signature = proxy.eth.send_raw_transaction(trx.rawTransaction)
        receipt = proxy.eth.wait_for_transaction_receipt(signature)

        self.contract = proxy.eth.contract(
            address=receipt.contractAddress,
            abi=contract.abi
        )

    
    def test_balanceOf(self):
        account = proxy.eth.account.create()

        solana_account = self.wrapper.get_neon_account_address(account.address)
        self.assertFalse(self.account_exists(solana_account))

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = self.contract.functions.balanceOf(account.address).buildTransaction({ "nonce": nonce })
        tx = proxy.eth.account.sign_transaction(tx, admin.key)

        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)

        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        self.assertFalse(self.account_exists(solana_account))


    def test_erc20_balanceOf(self):
        erc20 = self.wrapper.erc20_interface()

        account = proxy.eth.account.create()

        solana_account = self.wrapper.get_neon_account_address(account.address)
        self.assertFalse(self.account_exists(solana_account))

        token_account = self.wrapper.get_neon_erc20_account_address(account.address)
        self.assertFalse(self.account_exists(token_account))

        nonce = proxy.eth.get_transaction_count(admin.address)
        tx = erc20.functions.balanceOf(account.address).buildTransaction({ "nonce": nonce })
        tx = proxy.eth.account.sign_transaction(tx, admin.key)

        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)

        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)
        self.assertEqual(tx_receipt.status, 1)

        self.assertFalse(self.account_exists(solana_account))
        self.assertFalse(self.account_exists(token_account))

 

if __name__ == '__main__':
    unittest.main()
