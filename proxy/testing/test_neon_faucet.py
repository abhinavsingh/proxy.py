# File: test_neon_faucet.py
# Test for the faucet service.

import unittest
import os
import io
import time
import subprocess
import requests
from web3 import Web3
from solcx import compile_source

from proxy.testing.testing_helpers import request_airdrop

issue = 'https://github.com/neonlabsorg/neon-evm/issues/166'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
user = proxy.eth.account.create(issue + '/user')
proxy.eth.default_account = admin.address
request_airdrop(admin.address)

ERC20_CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;
// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
contract SafeMath {
    function safeAdd(uint a, uint b) public pure returns (uint c) {
        c = a + b;
        require(c >= a);
    }
    function safeSub(uint a, uint b) public pure returns (uint c) {
        require(b <= a);
        c = a - b;
    }
}
// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
// ----------------------------------------------------------------------------
abstract contract ERC20Interface {
    function totalSupply() virtual public view returns (uint);
    function balanceOf(address tokenOwner) virtual public view returns (uint balance);
    function allowance(address tokenOwner, address spender) virtual public view returns (uint remaining);
    function transfer(address to, uint tokens) virtual public returns (bool success);
    function approve(address spender, uint tokens) virtual public returns (bool success);
    function transferFrom(address from, address to, uint tokens) virtual public returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
// ----------------------------------------------------------------------------
// ERC20 Token, with the addition of symbol, name and decimals
// assisted token transfers
// ----------------------------------------------------------------------------
contract TestToken is ERC20Interface, SafeMath {
    string public symbol;
    string public  name;
    uint8 public decimals;
    uint public _totalSupply;
    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;
    // ------------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------------
    constructor() {
        symbol = "TST";
        name = "TestToken";
        decimals = 18;
        _totalSupply = 100000000000000000000000000000000000000000;
        balances[msg.sender] = _totalSupply;
        emit Transfer(address(0), msg.sender, _totalSupply);
    }
    // ------------------------------------------------------------------------
    // Total supply
    // ------------------------------------------------------------------------
    function totalSupply() public override view returns (uint) {
        return _totalSupply - balances[address(0)];
    }
    // ------------------------------------------------------------------------
    // Get the token balance for account tokenOwner
    // ------------------------------------------------------------------------
    function balanceOf(address tokenOwner) public override view returns (uint balance) {
        return balances[tokenOwner];
    }
    // ------------------------------------------------------------------------
    // Transfer the balance from token owner's account to receiver account
    // - Owner's account must have sufficient balance to transfer
    // - 0 value transfers are allowed
    // ------------------------------------------------------------------------
    function transfer(address receiver, uint tokens) public override returns (bool success) {
        balances[msg.sender] = safeSub(balances[msg.sender], tokens);
        balances[receiver] = safeAdd(balances[receiver], tokens);
        emit Transfer(msg.sender, receiver, tokens);
        return true;
    }
    // ------------------------------------------------------------------------
    // Token owner can approve for spender to transferFrom(...) tokens
    // from the token owner's account
    //
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
    // recommends that there are no checks for the approval double-spend attack
    // as this should be implemented in user interfaces
    // ------------------------------------------------------------------------
    function approve(address spender, uint tokens) public override returns (bool success) {
        allowed[msg.sender][spender] = tokens;
        emit Approval(msg.sender, spender, tokens);
        return true;
    }
    // ------------------------------------------------------------------------
    // Transfer tokens from sender account to receiver account
    //
    // The calling account must already have sufficient tokens approve(...)-d
    // for spending from sender account and
    // - From account must have sufficient balance to transfer
    // - Spender must have sufficient allowance to transfer
    // - 0 value transfers are allowed
    // ------------------------------------------------------------------------
    function transferFrom(address sender, address receiver, uint tokens) public override returns (bool success) {
        balances[sender] = safeSub(balances[sender], tokens);
        allowed[sender][msg.sender] = safeSub(allowed[sender][msg.sender], tokens);
        balances[receiver] = safeAdd(balances[receiver], tokens);
        emit Transfer(sender, receiver, tokens);
        return true;
    }
    // ------------------------------------------------------------------------
    // Returns the amount of tokens approved by the owner that can be
    // transferred to the spender's account
    // ------------------------------------------------------------------------
    function allowance(address tokenOwner, address spender) public override view returns (uint remaining) {
        return allowed[tokenOwner][spender];
    }
}
'''

class Test_Neon_Faucet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)
        cls.compile_erc20_contract(cls)
        cls.token_a = cls.deploy_erc20_token(cls, 'A')
        cls.token_b = cls.deploy_erc20_token(cls, 'B')

    def compile_erc20_contract(self):
        print('Compiling ERC20 contract...')
        compiled_contract = compile_source(ERC20_CONTRACT_SOURCE)
        contract_id, contract_interface = compiled_contract.popitem()
        self.contract = contract_interface

    def deploy_erc20_token(self, name):
        print('Deploying ERC20 token...')
        erc20 = proxy.eth.contract(abi=self.contract['abi'], bytecode=self.contract['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, admin.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print('Token', name, '=', tx_deploy_receipt.contractAddress)
        return tx_deploy_receipt.contractAddress

    # @unittest.skip("a.i.")
    def test_neon_faucet_00_ping(self):
        print()
        url = '{}/request_ping'.format(os.environ['FAUCET_URL'])
        print(url)
        data = '{"ping": "Hello"}'
        r = requests.post(url, data=data)
        if not r.ok:
            print('Response:', r.status_code)
        assert(r.ok)

    # @unittest.skip("a.i.")
    def test_neon_faucet_01_version(self):
        print()
        url = '{}/request_version'.format(os.environ['FAUCET_URL'])
        r = requests.post(url)
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

    @unittest.skip("a.i.")
    def test_neon_faucet_04_erc20(self):
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
