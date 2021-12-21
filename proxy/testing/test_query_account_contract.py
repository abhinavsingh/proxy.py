## File: test_query_account_contract.py
## Integration test for the QueryAccount smart contract.
##
## QueryAccount precompiled contract methods:
##------------------------------------------
## owner(uint256)              => 0xa123c33e
## length(uint256)             => 0xaa8b99d2
## lamports(uint256)           => 0x748f2d8a
## executable(uint256)         => 0xc219a785
## rent_epoch(uint256)         => 0xc4d369b5
## data(uint256,uint64,uint64) => 0x43ca5161
##------------------------------------------

import unittest
import os
from web3 import Web3
from solcx import install_solc
install_solc(version='0.7.6')
from solcx import compile_source

issue = 'https://github.com/neonlabsorg/neon-evm/issues/360'
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create(issue + '/admin')
proxy.eth.default_account = admin.address

# Address: HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU (a token mint account)
# uint256: 110178555362476360822489549210862241441608066866019832842197691544474470948129

# Address: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA (owner of the account)
# uint256: 3106054211088883198575105191760876350940303353676611666299516346430146937001

CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract QueryAccount {
    address constant precompiled = 0xff00000000000000000000000000000000000002;

    // Takes a Solana address, treats it as an address of an account.
    // Returns the account's owner Solana address (32 bytes).
    function owner(uint256 solana_address) public view returns (uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("owner(uint256)", solana_address));
        require(success, "QueryAccount.owner failed");
        return to_uint256(result);
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the length of the account's data (8 bytes).
    function length(uint256 solana_address) public view returns (uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("length(uint256)", solana_address));
        require(success, "QueryAccount.length failed");
        return to_uint256(result);
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the funds in lamports of the account.
    function lamports(uint256 solana_address) public view returns (uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("lamports(uint256)", solana_address));
        require(success, "QueryAccount.lamports failed");
        return to_uint256(result);
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the executable flag of the account.
    function executable(uint256 solana_address) public view returns (bool) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("executable(uint256)", solana_address));
        require(success, "QueryAccount.executable failed");
        return to_bool(result);
    }

    // Takes a Solana address, treats it as an address of an account.
    // Returns the rent epoch of the account.
    function rent_epoch(uint256 solana_address) public view returns (uint256) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("rent_epoch(uint256)", solana_address));
        require(success, "QueryAccount.rent_epoch failed");
        return to_uint256(result);
    }

    // Takes a Solana address, treats it as an address of an account,
    // also takes an offset and length of the account's data.
    // Returns a chunk of the data (length bytes).
    function data(uint256 solana_address, uint64 offset, uint64 len) public view returns (bytes memory) {
        (bool success, bytes memory result) = precompiled.staticcall(abi.encodeWithSignature("data(uint256,uint64,uint64)", solana_address, offset, len));
        require(success, "QueryAccount.data failed");
        return result;
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
    QueryAccount query;

    constructor() {
        query = new QueryAccount();
    }

    function test_metadata_ok() public view returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;

        uint256 golden_ownr = 3106054211088883198575105191760876350940303353676611666299516346430146937001;
        uint256 golden_len = 82;
        uint256 golden_lamp = 1461600;
        bool golden_exec = false;
        uint256 golden_repoch = 0;

        uint256 ownr = query.owner(solana_address);
        if (ownr != golden_ownr) {
            return false;
        }

        uint len = query.length(solana_address);
        if (len != golden_len) {
            return false;
        }

        uint256 lamp = query.lamports(solana_address);
        if (lamp != golden_lamp) {
            return false;
        }

        bool exec = query.executable(solana_address);
        if (exec != golden_exec) {
            return false;
        }

        uint256 repoch = query.rent_epoch(solana_address);
        if (repoch != golden_repoch) {
            return false;
        }

        return true;
    }

    function test_metadata_nonexistent_account() public view returns (bool) {
        uint256 solana_address = 90000; // should not exist
        bool ok = false;

        try query.owner(solana_address) { ok = false; } catch { ok = true; /* expected exception */ }
        if (!ok) { return ok; }

        try query.length(solana_address) { ok = false; } catch { ok = true; /* expected exception */ }
        if (!ok) { return ok; }

        try query.lamports(solana_address) { ok = false; } catch { ok = true; /* expected exception */ }
        if (!ok) { return ok; }

        try query.executable(solana_address) { ok = false; } catch { ok = true; /* expected exception */ }
        if (!ok) { return ok; }

        try query.rent_epoch(solana_address) { ok = false; } catch { ok = true; /* expected exception */ }

        return ok;
    }

    function test_data_ok() public view returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        byte b0 = 0x71;
        byte b1 = 0x33;
        byte b2 = 0xc6;
        byte b3 = 0x12;

        // Test getting subset of data
        uint64 offset = 20;
        uint64 len = 4;
        bytes memory result = query.data(solana_address, offset, len);
        if (result.length != 4) {
            return false;
        }
        if (result[0] != b0) {
            return false;
        }
        if (result[1] != b1) {
            return false;
        }
        if (result[2] != b2) {
            return false;
        }
        if (result[3] != b3) {
            return false;
        }
        // Test getting full data
        offset = 0;
        len = 82;
        result = query.data(solana_address, offset, len);
        if (result.length != 82) {
            return false;
        }

        return true;
    }

    function test_data_nonexistent_account() public view returns (bool) {
        uint256 solana_address = 90000; // hopefully does not exist
        uint64 offset = 0;
        uint64 len = 1;
        try query.data(solana_address, offset, len) { } catch {
            return true; // expected exception
        }
        return false;
    }

    function test_data_too_big_offset() public view returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        uint64 offset = 200; // data len is 82
        uint64 len = 1;
        try query.data(solana_address, offset, len) { } catch {
            return true; // expected exception
        }
        return false;
    }

    function test_data_too_big_length() public view returns (bool) {
        uint256 solana_address = 110178555362476360822489549210862241441608066866019832842197691544474470948129;
        uint64 offset = 0;
        uint64 len = 200; // data len is 82
        try query.data(solana_address, offset, len) { } catch {
            return true; // expected exception
        }
        return false;
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

    @unittest.skip("Temporatily")
    def test_metadata_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_metadata_ok = query.functions.test_metadata_ok().call()
        assert(get_metadata_ok)

    @unittest.skip("Temporatily")
    def test_metadata_nonexistent_account(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_metadata_nonexistent_account = query.functions.test_metadata_nonexistent_account().call()
        assert(get_metadata_nonexistent_account)

    @unittest.skip("Temporatily")
    def test_data_ok(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_ok = query.functions.test_data_ok().call()
        assert(get_data_ok)

    @unittest.skip("Temporatily")
    def test_data_nonexistent_account(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_nonexistent_account = query.functions.test_data_nonexistent_account().call()
        assert(get_data_nonexistent_account)

    @unittest.skip("Temporatily")
    def test_data_too_big_offset(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_too_big_offset = query.functions.test_data_too_big_offset().call()
        assert(get_data_too_big_offset)

    @unittest.skip("Temporatily")
    def test_data_too_big_length(self):
        print
        query = proxy.eth.contract(address=self.contract_address, abi=self.contract['abi'])
        get_data_too_big_length = query.functions.test_data_too_big_length().call()
        assert(get_data_too_big_length)

if __name__ == '__main__':
    unittest.main()
