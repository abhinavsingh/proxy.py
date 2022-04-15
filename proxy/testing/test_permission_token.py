import os
import unittest
from solana.rpc.api import Client as SolanaClient
from ..common_neon.permission_token import PermissionToken
from ..common_neon.solana_interactor import SolanaInteractor
from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
from web3 import Web3
from solana.rpc.commitment import Confirmed
from ..environment import ELF_PARAMS

from .testing_helpers import request_airdrop

ALLOWANCE_TOKEN_ADDR = ELF_PARAMS.get("NEON_PERMISSION_ALLOWANCE_TOKEN", '')
DENIAL_TOKEN_ADDR = ELF_PARAMS.get("NEON_PERMISSION_DENIAL_TOKEN", '')


class TestPermissionToken(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solana = SolanaInteractor(os.environ['SOLANA_URL'])
        cls.mint_authority_file = "/spl/bin/evm_loader-keypair.json"
        proxy_url = os.environ['PROXY_URL']
        cls.proxy = Web3(Web3.HTTPProvider(proxy_url))
        cls.eth_account = cls.proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/468')
        request_airdrop(cls.eth_account.address)

        cls.payer = SolanaAccount()
        client = SolanaClient(os.environ['SOLANA_URL'])
        client.request_airdrop(cls.payer.public_key(), 1000_000_000_000, Confirmed)
        cls.allowance_token = PermissionToken(cls.solana, PublicKey(ALLOWANCE_TOKEN_ADDR))
        cls.denial_token = PermissionToken(cls.solana, PublicKey(DENIAL_TOKEN_ADDR))

    def test_mint_permission_tokens(self):
        """
        Should receive all permission tokens minted by authority
        """
        new_acc = self.proxy.eth.account.create(f'test_mint_permission_tokens')
        allowance_amount = 1234
        denial_amount = 4321
        self.allowance_token.mint_to(allowance_amount, new_acc.address, self.mint_authority_file, self.payer)
        self.denial_token.mint_to(denial_amount, new_acc.address, self.mint_authority_file, self.payer)
        self.assertEqual(self.allowance_token.get_balance(new_acc.address), allowance_amount)
        self.assertEqual(self.denial_token.get_balance(new_acc.address), denial_amount)
