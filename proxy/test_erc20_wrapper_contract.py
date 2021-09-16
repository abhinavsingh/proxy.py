## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

import unittest
import os
from web3 import Web3
from solcx import install_solc

# install_solc(version='latest')
install_solc(version='0.7.6')
from solcx import compile_source

EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197')
proxy.eth.default_account = eth_account.address

NAME = 'NEON'
SYMBOL = 'NEO'

# token_mint::id = "HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU" in Base58
# Convert Base58 to hex number:
TOKEN_MINT = bytes.fromhex('f396da383e57418540f8caa598584f49a3b50d256f75cb6d94d101681d6d9d21')

# Standard interface of ERC20 contract to generate ABI for wrapper
ERC20_INTERFACE_SOURCE = '''
pragma solidity >=0.7.0;

interface IERC20 {
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
'''

# Copy of contract: https://github.com/neonlabsorg/neon-evm/blob/develop/evm_loader/SPL_ERC20_Wrapper.sol
ERC20_WRAPPER_SOURCE = '''
pragma solidity >=0.7.0;

interface IERC20 {
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    function approveSolana(bytes32 spender, uint64 value) external returns (bool);
    event ApprovalSolana(address indexed owner, bytes32 indexed spender, uint64 value);
}

/*abstract*/ contract NeonERC20Wrapper /*is IERC20*/ {
    address constant NeonERC20 = 0xff00000000000000000000000000000000000001;

    string public name;
    string public symbol;
    bytes32 public tokenMint;

    constructor(
        string memory _name,
        string memory _symbol,
        bytes32 _tokenMint
    ) {
        name = _name;
        symbol = _symbol;
        tokenMint = _tokenMint;
    }

    fallback() external {
        bytes memory call_data = abi.encodePacked(tokenMint, msg.data);
        (bool success, bytes memory result) = NeonERC20.delegatecall(call_data);

        require(success, string(result));

        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
'''

class Test_erc20_wrapper_contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/197")
        print('eth_account.key:', eth_account.key.hex())
        print('eth_account.address:', eth_account.address)
        cls.deploy_erc20_wrapper_contract(cls)

    def deploy_erc20_wrapper_contract(self):
        compiled_interface = compile_source(ERC20_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        compiled_wrapper = compile_source(ERC20_WRAPPER_SOURCE)
        wrapper_id, wrapper_interface = compiled_wrapper.popitem()
        self.wrapper = wrapper_interface
        
        erc20 = proxy.eth.contract(abi=self.wrapper['abi'], bytecode=wrapper_interface['bin'])
        trx_constructor = erc20.constructor(NAME, SYMBOL, TOKEN_MINT).buildTransaction(
            {'nonce': proxy.eth.get_transaction_count(proxy.eth.default_account)}
        )
        trx_deploy = proxy.eth.account.sign_transaction(trx_constructor, eth_account.key)
        #print('trx_deploy:', trx_deploy)
        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        #print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        #print('trx_deploy_receipt:', trx_deploy_receipt)
        print('deploy status:', trx_deploy_receipt.status)
        self.contract_address= trx_deploy_receipt.contractAddress

    def test_erc20_name(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.wrapper['abi'])
        name = erc20.functions.name().call()
        self.assertEqual(name, NAME)

    def test_erc20_symbol(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.wrapper['abi'])
        sym = erc20.functions.symbol().call()
        self.assertEqual(sym, SYMBOL)

    def test_erc20_decimals(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.interface['abi'])
        decs = erc20.functions.decimals().call()
        self.assertEqual(decs, 9)

    @unittest.skip("a.i.")
    def test_02_execute_with_right_nonce(self):
        print("\ntest_02_execute_with_right_nonce")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.store(147).buildTransaction({'nonce': right_nonce})
        print('trx_store:', trx_store)
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        print('trx_store_signed:', trx_store_signed)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        print('trx_store_hash:', trx_store_hash.hex())
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)
        print('trx_store_receipt:', trx_store_receipt)
        number = self.storage_contract.functions.retrieve().call()
        print('number:', number)
        self.assertEqual(number, 147)

    @unittest.skip("a.i.")
    def test_03_execute_with_low_gas(self):
        print("\ntest_03_execute_with_low_gas")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.store(148).buildTransaction({'nonce': right_nonce, 'gasPrice': 1})
        print('trx_store:', trx_store)
        trx_store['gas'] = trx_store['gas'] - 2 - EXTRA_GAS # less than estimated
        print('trx_store:', trx_store)
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        print('trx_store_signed:', trx_store_signed)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        print('trx_store_hash:', trx_store_hash.hex())
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)
        print('trx_store_receipt:', trx_store_receipt)
        self.assertEqual(trx_store_receipt['status'], 0)  # false Transaction mined but execution failed

    @unittest.skip("a.i.")
    def test_04_execute_with_bad_nonce(self):
        print("\ntest_04_execute_with_bad_nonce")
        bad_nonce = 1 + proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.store(147).buildTransaction({'nonce': bad_nonce})
        print('trx_store:', trx_store)
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        print('trx_store_signed:', trx_store_signed)
        try:
            trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
            print('trx_store_hash:', trx_store_hash)
            self.assertTrue(False)
        except Exception as e:
            print('type(e):', type(e))
            print('e:', e)
            import json
            response = json.loads(str(e).replace('\'', '\"').replace('None', 'null'))
            print('response:', response)
            print('code:', response['code'])
            self.assertEqual(response['code'], -32002)
            print('substring_err_147:', SUBSTRING_LOG_ERR_147)
            logs = response['data']['logs']
            print('logs:', logs)
            log = [s for s in logs if SUBSTRING_LOG_ERR_147 in s][0]
            print(log)
            self.assertGreater(len(log), len(SUBSTRING_LOG_ERR_147))
            file_name = 'src/entrypoint.rs'
            self.assertTrue(file_name in log)

    @unittest.skip("a.i.")
    def test_05_transfer_one_gwei(self):
        print("\ntest_05_transfer_one_gwei")
        eth_account_alice = proxy.eth.account.create('alice')
        eth_account_bob = proxy.eth.account.create('bob')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)

        alice_balance_before_transfer = proxy.eth.get_balance(eth_account_alice.address)
        bob_balance_before_transfer = proxy.eth.get_balance(eth_account_bob.address)
        print('alice_balance_before_transfer:', alice_balance_before_transfer)
        print('bob_balance_before_transfer:', bob_balance_before_transfer)
        one_gwei = 1_000_000_000
        print('one_gwei:', one_gwei)

        trx_transfer = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account_alice.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to=eth_account_bob.address,
            value=one_gwei),
            eth_account_alice.key
        )

        print('trx_transfer:', trx_transfer)
        trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
        print('trx_transfer_hash:', trx_transfer_hash.hex())
        trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
        print('trx_transfer_receipt:', trx_transfer_receipt)

        alice_balance_after_transfer = proxy.eth.get_balance(eth_account_alice.address)
        bob_balance_after_transfer = proxy.eth.get_balance(eth_account_bob.address)
        print('alice_balance_after_transfer:', alice_balance_after_transfer)
        print('bob_balance_after_transfer:', bob_balance_after_transfer)
        self.assertEqual(alice_balance_after_transfer, alice_balance_before_transfer - one_gwei)
        self.assertEqual(bob_balance_after_transfer, bob_balance_before_transfer + one_gwei)

    @unittest.skip("a.i.")
    def test_06_transfer_one_and_a_half_gweis(self):
        print("\ntest_06_transfer_one_and_a_half_gweis")
        eth_account_alice = proxy.eth.account.create('alice')
        eth_account_bob = proxy.eth.account.create('bob')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)

        alice_balance_before_transfer = proxy.eth.get_balance(eth_account_alice.address)
        bob_balance_before_transfer = proxy.eth.get_balance(eth_account_bob.address)
        print('alice_balance_before_transfer:', alice_balance_before_transfer)
        print('bob_balance_before_transfer:', bob_balance_before_transfer)
        one_and_a_half_gweis = 1_500_000_000
        print('one_and_a_half_gweis:', one_and_a_half_gweis)

        trx_transfer = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account_alice.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to=eth_account_bob.address,
            value=one_and_a_half_gweis),
            eth_account_alice.key
        )

        print('trx_transfer:', trx_transfer)
        trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
        print('trx_transfer_hash:', trx_transfer_hash.hex())
        trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
        print('trx_transfer_receipt:', trx_transfer_receipt)

        alice_balance_after_transfer = proxy.eth.get_balance(eth_account_alice.address)
        bob_balance_after_transfer = proxy.eth.get_balance(eth_account_bob.address)
        print('alice_balance_after_transfer:', alice_balance_after_transfer)
        print('bob_balance_after_transfer:', bob_balance_after_transfer)
        print('check https://github.com/neonlabsorg/neon-evm/issues/210')
        one_gwei = 1_000_000_000
        print('one_gwei:', one_gwei)
        self.assertEqual(alice_balance_after_transfer, alice_balance_before_transfer - one_gwei)
        self.assertEqual(bob_balance_after_transfer, bob_balance_before_transfer + one_gwei)

    @unittest.skip("a.i.")
    def test_07_execute_long_transaction(self):
        print("\ntest_07_execute_long_transaction")
        trx_initValue = self.test_185_solidity_contract.functions.initValue('185 init value').buildTransaction({'nonce': proxy.eth.get_transaction_count(proxy.eth.default_account)})
        print('trx_initValue:', trx_initValue)
        trx_initValue_signed = proxy.eth.account.sign_transaction(trx_initValue, eth_account.key)
        print('trx_initValue_signed:', trx_initValue_signed)
        trx_initValue_hash = proxy.eth.send_raw_transaction(trx_initValue_signed.rawTransaction)
        print('trx_initValue_hash:', trx_initValue_hash.hex())
        trx_initValue_receipt = proxy.eth.wait_for_transaction_receipt(trx_initValue_hash)
        print('trx_initValue_hash_receipt:', trx_initValue_receipt)

        value = self.test_185_solidity_contract.functions.getValue().call()
        print('value:', value.hex())
        self.assertEqual(value.hex(), '36fb9ea61aba18555110881836366c8d7701685174abe4926673754580ee26c5')

        from datetime import datetime
        start = datetime.now()

        times_to_calculate = 10
        trx_calculate = self.test_185_solidity_contract.functions.calculateKeccakAndStore(times_to_calculate).buildTransaction({'nonce': proxy.eth.get_transaction_count(proxy.eth.default_account)})
        print('trx_calculate:', trx_calculate)
        trx_calculate_signed = proxy.eth.account.sign_transaction(trx_calculate, eth_account.key)
        print('trx_calculate_signed:', trx_calculate_signed)
        trx_calculate_hash = proxy.eth.send_raw_transaction(trx_calculate_signed.rawTransaction)
        print('trx_calculate_hash:', trx_calculate_hash.hex())
        trx_calculate_receipt = proxy.eth.wait_for_transaction_receipt(trx_calculate_hash)
        print('trx_calculate_hash_receipt:', trx_calculate_receipt)

        time_duration = datetime.now() - start

        value = self.test_185_solidity_contract.functions.getValue().call()
        print('value:', value.hex())
        self.assertEqual(value.hex(), 'e6d201b1e3aab3b3cc100ea7a0b76fcbb3c2fef88fc4e540f9866d8d2e6e2131')
        print('times_to_calculate:', times_to_calculate)
        print('time_duration:', time_duration)


if __name__ == '__main__':
    unittest.main()
