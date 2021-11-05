import unittest
import os
from web3 import Web3
from proxy.plugin.solana_rest_api_tools import read_elf_params

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))

class Test_Environment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf_params = {}
        read_elf_params(cls.elf_params)

    def test_read_elf_params(self):
        print("\n\nhttps://github.com/neonlabsorg/neon-evm/issues/347")
        elf_params = {}
        read_elf_params(elf_params)

        neon_chain_id = elf_params.get('NEON_CHAIN_ID', None)
        self.assertTrue(neon_chain_id is not None)
        self.assertEqual(neon_chain_id, os.environ.get('NEON_CHAIN_ID', None))

        neon_token_mint = elf_params.get('NEON_TOKEN_MINT', None)
        self.assertTrue(neon_token_mint is not None)
        self.assertEqual(neon_token_mint, os.environ.get('NEON_TOKEN_MINT', None))

        neon_pool_base = elf_params.get('NEON_POOL_BASE', None)
        self.assertTrue(neon_pool_base is not None)
        self.assertEqual(neon_pool_base, os.environ.get('NEON_POOL_BASE', None))

    def test_neon_chain_id(self):
        print("\n\nhttps://github.com/neonlabsorg/neon-evm/issues/347")
        neon_chain_id = os.environ.get('NEON_CHAIN_ID', None)
        print(f"NEON_CHAIN_ID = {neon_chain_id}")
        self.assertTrue(neon_chain_id is not None)

        eth_chainId: int = proxy.eth.chain_id
        print(f"eth_chainId = {eth_chainId}")
        self.assertEqual(eth_chainId, int(neon_chain_id))

        net_version: str = proxy.net.version
        print(f"net_version = {net_version}")
        self.assertEqual(net_version, neon_chain_id)

