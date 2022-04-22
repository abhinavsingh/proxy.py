# File: test_neon_faucet.py
# Test for the faucet service.

import unittest
import os
import requests
from web3 import Web3

issue = 'https://github.com/neonlabsorg/neon-evm/issues/166'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
user = proxy.eth.account.create(issue + '/user')
proxy.eth.default_account = admin.address

class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)

    # @unittest.skip("a.i.")
    def test_neon_faucet_00_ping(self):
        print()
        url = '{}/request_ping'.format(os.environ['FAUCET_URL'])
        print(url)
        data = '{"ping": "Hello"}'
        r = requests.get(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)

    # @unittest.skip("a.i.")
    def test_neon_faucet_01_version(self):
        print()
        url = '{}/request_version'.format(os.environ['FAUCET_URL'])
        r = requests.get(url)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)

    # @unittest.skip("a.i.")
    def test_neon_faucet_02_neon_in_galans(self):
        print()
        url = '{}/request_neon_in_galans'.format(os.environ['FAUCET_URL'])
        balance_before = proxy.eth.get_balance(user.address)
        print('NEO balance before:', balance_before)
        data = '{"wallet": "' + user.address + '", "amount": 99999}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        # Check
        balance_after = proxy.eth.get_balance(user.address)
        print('NEO balance after:', balance_after)
        print('NEO balance difference:', balance_before - balance_after)
        self.assertEqual(balance_after, 99999000000000)

    # @unittest.skip("a.i.")
    def test_neon_faucet_03_neon(self):
        print()
        url = '{}/request_neon'.format(os.environ['FAUCET_URL'])
        balance_before = proxy.eth.get_balance(user.address)
        print('NEO balance before:', balance_before)
        data = '{"wallet": "' + user.address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        # Check
        balance_after = proxy.eth.get_balance(user.address)
        print('NEO balance after:', balance_after)
        print('NEO balance difference:', balance_after - balance_before)
        self.assertEqual(balance_after - balance_before, 1000000000000000000)

    # @unittest.skip("a.i.")
    def test_neon_faucet_04_erc20_list(self):
        print()
        url = '{}/request_erc20_list'.format(os.environ['FAUCET_URL'])
        r = requests.get(url)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        self.assertEqual(r.text, '["0xB521b9F3484deF53545F276F1DAA50ef0Ca82E2d","0x8a2a66CA0E5D491A001957edD45A6350bC76D708","0x914782059DC42d4E590aeFCfdbF004B2EcBB9fAA","0x7A7510b9b18241C788a7aAE8299D1fA6010D8128"]')

    @unittest.skip("a.i.")
    def test_neon_faucet_06_erc20_single(self):
        print()
        url = '{}/request_erc20'.format(os.environ['FAUCET_URL'])
        token = '0xB521b9F3484deF53545F276F1DAA50ef0Ca82E2d'
        before = self.get_token_balance(token, user.address)
        print('token A balance before:', before)
        data = '{"wallet": "' + user.address + '", "token_addr": "' + token + '", "amount": 1}'
        print('data:', data)
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        after = self.get_token_balance(token, user.address)
        print('token A balance after:', after)
        self.assertEqual(after - before, 1000000000000000000)

    @unittest.skip("a.i.")
    def test_neon_faucet_05_erc20_all(self):
        print()
        url = '{}/request_erc20'.format(os.environ['FAUCET_URL'])
        a_before = self.get_token_balance(self.token_a, user.address)
        b_before = self.get_token_balance(self.token_b, user.address)
        print('token A balance before:', a_before)
        print('token B balance before:', b_before)
        data = '{"wallet": "' + user.address + '", "amount": 1}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)
        a_after = self.get_token_balance(self.token_a, user.address)
        b_after = self.get_token_balance(self.token_b, user.address)
        print('token A balance after:', a_after)
        print('token B balance after:', b_after)
        self.assertEqual(a_after - a_before, 1000000000000000000)
        self.assertEqual(b_after - b_before, 1000000000000000000)

    # Returns balance of a token account.
    # Note: the result is in 10E-18 fractions.
    def get_token_balance(self, token_address, address):
        erc20 = proxy.eth.contract(address=token_address, abi=self.contract['abi'])
        return erc20.functions.balanceOf(address).call()

if __name__ == '__main__':
    unittest.main()
