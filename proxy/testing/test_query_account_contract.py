## File: test_query_account_contract.py
## Integration test for the QueryAccount smart contract.
##
## QueryAccount precompiled contract methods:
##------------------------------------------
## cache(uint256,uint64,uint64) => 0x2b3c8322
## owner(uint256)               => 0xa123c33e
## length(uint256)              => 0xaa8b99d2
## lamports(uint256)            => 0x748f2d8a
## executable(uint256)          => 0xc219a785
## rent_epoch(uint256)          => 0xc4d369b5
## data(uint256,uint64,uint64)  => 0x43ca5161
##------------------------------------------

import unittest
import os
from web3 import Web3
from solcx import compile_source

from proxy.testing.testing_helpers import request_airdrop

issue = 'https://github.com/neonlabsorg/neon-evm/issues/360'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
proxy.eth.default_account = admin.address
request_airdrop(admin.address)

# Address: HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU (a token mint account)
# uint256: 110178555362476360822489549210862241441608066866019832842197691544474470948129

# Address: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (owner of the account)
# uint256: 3106054211088883198575105191760876350940303353676611666299516346430146937001

CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

library QueryAccount {
    address constant precompiled = 0xff00000000000000000000000000000000000002;

    // Takes a Solana address, treats it as an address of an account.
    // Puts the metadata and a chunk of data into the cache.
    function cache(uint256 solana_address, uint64 offset, uint64 len) internal returns (bool) {
        (bool success, bytes memory _dummy) = precompiled.staticcall(abi.encodeWithSignature("cache(uint256,uint64,uint64)", solana_address, offset, len));
        return success;
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the account's owner Solana address (32 bytes).
    function owner(uint256 solana_address) internal view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("owner(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the length of the account's data (8 bytes).
    function length(uint256 solana_address) internal view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("length(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the funds in lamports of the account.
    function lamports(uint256 solana_address) internal view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("lamports(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the executable flag of the account.
    function executable(uint256 solana_address) internal view returns (bool, bool) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("executable(uint256)", solana_address));
        return (success, to_bool(result));
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the rent epoch of the account.
    function rent_epoch(uint256 solana_address) internal view returns (bool, uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("rent_epoch(uint256)", solana_address));
        return (success, to_uint256(result));
    }

    // Takes a Solana address, treats it as an address of an account,
    // also takes an offset and length of the account's data.
    // Returns a chunk of the data (length bytes).
    function data(uint256 solana_address, uint64 offset, uint64 len) internal view returns (bool, bytes memory) {
        return precompiled.staticcall(abi.encodeWithSignature("data(uint256,uint64,uint64)", solana_address, offset, len));
    }

    function to_uint256(bytes memory bb) private pure returns (uint256 result) {
        assembly {
            result := mload(add(bb, 32))
        }
    }

    function to_bool(bytes memory bb) private pure returns (bool result) {
        assembly {
            result := mload(add(bb, 32))
        }
    }
}

contract TestQueryAccount {
    uint256 constant solana_account = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
    uint256 constant missing_account = 90000;
    uint64 constant golden_data_len = 82;

    function test_cache() public returns (bool) {
        // Put
        bool ok = QueryAccount.cache(solana_account, 0, 64);
        if (!ok) { return false; }

        // Replace
        ok = QueryAccount.cache(solana_account, 0, golden_data_len);
        if (!ok) { return false; }

        // Zero length
        ok = QueryAccount.cache(solana_account, 0, 0);
        if (ok) { return false; }

        // Length more than maximal limit (8kB)
        ok = QueryAccount.cache(solana_account, 0, 10*1024);
        if (ok) { return false; }

        // Length more than length of the account data
        ok = QueryAccount.cache(solana_account, 0, 200);
        if (ok) { return false; }

        // Offset too big
        ok = QueryAccount.cache(solana_account, 200, 16);
        if (ok) { return false; }

        // Nonexistent account
        ok = QueryAccount.cache(missing_account, 0, 1);
        if (ok) { return false; }

        return true;
    }

    function test_noncached() public returns (bool) {
        bool ok;
        uint256 _u;
        bool _b;
        bytes memory _m;

        (ok, _u) = QueryAccount.owner(solana_account);
        if (ok) { return false; }

        (ok, _u) = QueryAccount.length(solana_account);
        if (ok) { return false; }

        (ok, _u) = QueryAccount.lamports(solana_account);
        if (ok) { return false; }

        (ok, _b) = QueryAccount.executable(solana_account);
        if (ok) { return false; }

        (ok, _u) = QueryAccount.rent_epoch(solana_account);
        if (ok) { return false; }

        (ok, _m) = QueryAccount.data(solana_account, 0, 1);
        if (ok) { return false; }

        return true;
    }

    function test_metadata_ok() public returns (bool) {
        bool ok = QueryAccount.cache(solana_account, 0, 64);
        if (!ok) { return false; }

        uint256 golden_owner = 3106054211088883198575105191760876350940303353676611666299516346430146937001;
        uint256 golden_lamp = 1461600;
        bool golden_exec = false;

        uint256 ownr;
        (ok, ownr) = QueryAccount.owner(solana_account);
        if (!ok || ownr != golden_owner) {
            return false;
        }

        uint len;
        (ok, len) = QueryAccount.length(solana_account);
        if (!ok || len != golden_data_len) {
            return false;
        }

        uint256 lamp;
        (ok, lamp) = QueryAccount.lamports(solana_account);
        if (!ok || lamp != golden_lamp) {
            return false;
        }

        bool exec;
        (ok, exec) = QueryAccount.executable(solana_account);
        if (!ok || exec != golden_exec) {
            return false;
        }

        uint256 _repoch; // epoch may change, so there is no golden value
        (ok, _repoch) = QueryAccount.rent_epoch(solana_account);
        if (!ok) {
            return false;
        }

        return true;
    }

    function test_data_ok() public returns (bool) {
        bool ok = QueryAccount.cache(solana_account, 0, golden_data_len);
        if (!ok) { return false; }

        bytes1[golden_data_len] memory golden =
            [to_byte(1), to_byte(0), to_byte(0), to_byte(0), to_byte(60), to_byte(0), to_byte(57), to_byte(43), to_byte(120), to_byte(125),
             to_byte(56), to_byte(168), to_byte(83), to_byte(209), to_byte(36), to_byte(5), to_byte(118), to_byte(52), to_byte(196),
             to_byte(60), to_byte(113), to_byte(51), to_byte(198), to_byte(18), to_byte(70), to_byte(29), to_byte(116), to_byte(254),
             to_byte(177), to_byte(127), to_byte(66), to_byte(72), to_byte(21), to_byte(82), to_byte(134), to_byte(192), to_byte(0),
             to_byte(160), to_byte(51), to_byte(190), to_byte(10), to_byte(144), to_byte(35), to_byte(0), to_byte(9), to_byte(1), to_byte(0),
             to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0),
             to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0),
             to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0), to_byte(0),
             to_byte(0), to_byte(0)];

        uint64 len;
        uint64 offset;
        bytes memory result;

        // Get full data
        len = golden_data_len;
        offset = 0;
        (ok, result) = QueryAccount.data(solana_account, offset, len);
        if (!ok || !equals(result, golden, offset, len)) {
            return false;
        }

        // Get mid-subset of data
        len = 40;
        offset = 20;
        (ok, result) = QueryAccount.data(solana_account, offset, len);
        if (!ok || !equals(result, golden, offset, len)) {
            return false;
        }

        // Get head of data
        len = 40;
        offset = 0;
        (ok, result) = QueryAccount.data(solana_account, offset, len);
        if (!ok || !equals(result, golden, offset, len)) {
            return false;
        }

        // Get tail of data
        len = 40;
        offset = golden_data_len - len;
        (ok, result) = QueryAccount.data(solana_account, offset, len);
        if (!ok || !equals(result, golden, offset, len)) {
            return false;
        }

        return true;
    }

    function test_data_wrong_range() public returns (bool) {
        bool ok = QueryAccount.cache(solana_account, 30, 20);
        if (!ok) { return false; }

        uint64 len;
        uint64 offset;
        bytes memory _m;

        // Query empty chunk
        len = 0;
        offset = 35;
        (ok, _m) = QueryAccount.data(solana_account, offset, len);
        if (ok) { return false; }

        // Query chunk wholly before the cached region
        len = 10;
        offset = 1;
        (ok, _m) = QueryAccount.data(solana_account, offset, len);
        if (ok) { return false; }

        // Query chunk wholly after the cached region
        len = 10;
        offset = 55;
        (ok, _m) = QueryAccount.data(solana_account, offset, len);
        if (ok) { return false; }

        // Query chunk overlapping the head of the cached region
        len = 20;
        offset = 20;
        (ok, _m) = QueryAccount.data(solana_account, offset, len);
        if (ok) { return false; }

        // Query chunk overlapping the tail of the cached region
        len = 20;
        offset = 40;
        (ok, _m) = QueryAccount.data(solana_account, offset, len);
        if (ok) { return false; }

        // Query big chunk overlapping entire cached region
        len = 40;
        offset = 20;
        (ok, _m) = QueryAccount.data(solana_account, offset, len);
        if (ok) { return false; }

        return true;
    }

    function to_byte(uint8 i) public pure returns (bytes1) {
        return abi.encodePacked(i)[0];
    }

    function equals(bytes memory data, bytes1[golden_data_len] memory golden, uint64 offset, uint64 length) private pure returns (bool) {
        if (data.length != length) { return false; }

        for (uint i = 0; i < length; i++) {
            if (data[i] != golden[i+offset]) {
                return false;
            }
        }

        return true;
    }
}
'''

class Test_Query_Account_Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print('\n\n' + issue)
        print('admin address:', admin.address)
        cls.deploy_contract(cls)

    def deploy_contract(self):
        compiled = compile_source(CONTRACT_SOURCE)
        id, interface = compiled.popitem()
        self.contract = interface
        contract = proxy.eth.contract(abi=self.contract['abi'], bytecode=self.contract['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = contract.constructor().buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, admin.key)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        self.contract_address = tx_deploy_receipt.contractAddress
        print('contract address:', self.contract_address)

    # @unittest.skip("a.i.")
    def test_cache(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_cache().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_noncached(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_noncached().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_metadata_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_metadata_ok().call()
        assert(ok)

    @unittest.skip("a.i.")
    def test_data_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_data_ok().call()
        assert(ok)

    # @unittest.skip("a.i.")
    def test_data_wrong_range(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        ok = query.functions.test_data_wrong_range().call()
        assert(ok)

if __name__ == '__main__':
    unittest.main()
