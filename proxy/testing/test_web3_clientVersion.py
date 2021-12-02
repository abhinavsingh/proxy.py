import unittest
import os
from web3 import Web3

proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create('web3_clientVersion')
proxy.eth.default_account = eth_account.address

neon_revision = os.environ.get('NEON_REVISION', 'env var NEON_REVISION is not set')


class Test_web3_clientVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/205')
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())

    def test_web3_clientVersion(self):
        print('check tag Neon/v in web3_clientVersion')
        web3_clientVersion = proxy.clientVersion
        print('web3_clientVersion:', web3_clientVersion)
        self.assertTrue(web3_clientVersion.startswith('Neon/v'))
        print('check for neon_revision:', neon_revision)
        self.assertTrue(web3_clientVersion.endswith(neon_revision))


if __name__ == '__main__':
    unittest.main()
