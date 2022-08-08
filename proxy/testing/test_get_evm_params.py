import os
import unittest
from ..common_neon.web3 import NeonWeb3 as Web3

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))

class TestGetEvmParam(unittest.TestCase):
    def test_all_cases(self):
        print(f'Neon-EVM Params: {proxy.neon.getEvmParams()}')

