import unittest
import os
from web3 import Web3
from solcx import install_solc

# install_solc(version='latest')
install_solc(version='0.7.0')
from solcx import compile_source

proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/140')
proxy.eth.default_account = eth_account.address


class Test140(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/140")
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())

    def test_block_number_with_tag_latest(self):
        print("\n\ntest_block_number_with_tag_latest")
        print("check tag latest in eth_getBlockByNumber")
        proxy.eth.default_block = 'latest'
        try:
            print('proxy.eth.block_number:', proxy.eth.block_number)
        except Exception as e:
            print('type(e):', type(e))
            print('Exception:', e)
            self.assertTrue(False)

    def test_block_number_with_tag_earliest(self):
        print("\n\ntest_block_number_with_tag_latest")
        print("check tag earliest in eth_getBlockByNumber")
        proxy.eth.default_block = 'earliest'
        self.assertRaises(Exception, proxy.eth.block_number)

    def test_block_number_with_tag_pending(self):
        print("\n\ntest_block_number_with_tag_latest")
        print("check tag pending in eth_getBlockByNumber")
        proxy.eth.default_block = 'pending'
        self.assertRaises(Exception, proxy.eth.block_number)


if __name__ == '__main__':
    unittest.main()
