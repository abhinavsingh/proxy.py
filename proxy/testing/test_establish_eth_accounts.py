import unittest
import eth_account
import eth_typing
import eth_utils
import os
from web3 import Web3

NEW_USER_AIRDROP_AMOUNT = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))


class TestEstablishEthAccounts(unittest.TestCase):

    def setUp(self) -> None:
        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        self.proxy = Web3(Web3.HTTPProvider(proxy_url))

    def test_metamask_creates_account(self):

        account: eth_account.account.LocalAccount = eth_account.account.Account.create()
        block_number: eth_typing.BlockNumber = self.proxy.eth.get_block_number()
        balance_wei = self.proxy.eth.get_balance(account.address, block_identifier=block_number)
        expected_wei = eth_utils.to_wei(NEW_USER_AIRDROP_AMOUNT, 'ether')
        self.assertEqual(expected_wei, balance_wei)
