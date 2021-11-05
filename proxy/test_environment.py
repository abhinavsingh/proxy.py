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

    def test_neon_chain_id(self):
        print("\n\nhttps://github.com/neonlabsorg/neon-evm/issues/347")
        neon_chain_id = self.elf_params.get('NEON_CHAIN_ID', None)
        print(f"NEON_CHAIN_ID = {neon_chain_id}")
        assert (neon_chain_id is not None)

        eth_chainId: int = proxy.eth.chain_id
        print(f"eth_chainId = {eth_chainId}")
        assert(eth_chainId == int(neon_chain_id))

        net_version: str = proxy.net.version
        print(f"net_version = {net_version}")
        assert (net_version == neon_chain_id)

