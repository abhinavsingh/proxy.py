import os
import unittest
from solana.rpc.api import Client as SolanaClient
from proxy.common_neon.permission_token import PermissionToken
from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
import json
from web3 import Web3
from solana.rpc.commitment import Confirmed

class TestPermissionToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solana = SolanaClient(os.environ['SOLANA_URL'])
        cls.mint_authority_file = "/spl/bin/evm_loader-keypair.json"
        proxy_url = os.environ['PROXY_URL']
        cls.proxy = Web3(Web3.HTTPProvider(proxy_url))
        cls.eth_account = cls.proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/468')

        cls.payer = SolanaAccount()
        cls.solana.request_airdrop(cls.payer.public_key(), 1000_000_000_000, Confirmed)
        cls.allowance_token = PermissionToken(cls.solana,
                                              PublicKey(os.environ['NEON_PERMISSION_ALLOWANCE_TOKEN']),
                                              cls.payer)

        cls.denial_token = PermissionToken(cls.solana,
                                           PublicKey(os.environ['NEON_PERMISSION_DENIAL_TOKEN']),
                                           cls.payer)

    def test_get_balance_non_existing_account(self):
        """
        Should return zero balance for non existing token-account
        """
        new_acc = self.proxy.eth.account.create(f'test_get_balance_non_existing_account')
        self.assertEqual(self.allowance_token.get_balance(new_acc.address), 0)
        self.assertEqual(self.denial_token.get_balance(new_acc.address), 0)

    def test_mint_permission_tokens(self):
        """
        Should receive all permission tokens minted by authority
        """
        new_acc = self.proxy.eth.account.create(f'test_mint_permission_tokens')
        allowance_amount = 1234
        denial_amount = 4321
        self.allowance_token.mint_to(allowance_amount, new_acc.address, self.mint_authority_file)
        self.denial_token.mint_to(denial_amount, new_acc.address, self.mint_authority_file)
        self.assertEqual(self.allowance_token.get_balance(new_acc.address), allowance_amount)
        self.assertEqual(self.denial_token.get_balance(new_acc.address), denial_amount)
