import unittest
import os
from web3 import Web3
from solcx import install_solc

# install_solc(version='latest')
install_solc(version='0.7.0')
from solcx import compile_source

EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/147')
proxy.eth.default_account = eth_account.address

SUBSTRING_LOG_ERR_147 = 'Invalid Ethereum transaction nonce:'

STORAGE_SOLIDITY_SOURCE_147 = '''
pragma solidity >=0.7.0 <0.9.0;
/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {
    uint256 number;
    /**
     * @dev Store value in variable
     * @param num value to store
     */
    function store(uint256 num) public {
        number = num;
    }
    /**
     * @dev Return value
     * @return value of 'number'
     */
    function retrieve() public view returns (uint256){
        return number;
    }
}
'''

SOLIDITY_SOURCE_185 = '''
pragma solidity >=0.7.0 <0.9.0;

contract test_185 {
    bytes public emprty_string = "";

    function getKeccakOfEmptyString() public view returns (bytes32 variant) {
        variant = keccak256(emprty_string);
    }
    
    bytes32 constant neonlabsHash = keccak256("neonlabs");

    function endlessCycle() public view returns (bytes32 variant) {
        variant = keccak256(emprty_string);
        for(;neonlabsHash != variant;) {
            variant = keccak256(abi.encodePacked(variant));
        }
        return variant;
    }

    bytes32 public value = "";
    
    function initValue(string memory s) public {
        value = keccak256(bytes(s));
    }

    function calculateKeccakAndStore(uint256 times) public {
        for(;times > 0; --times) {
            value = keccak256(abi.encodePacked(value));
        }
    }
    
    function getValue() public view returns (bytes32) {
        return value;
    }
    
}
'''


class Test_eth_sendRawTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/147")
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        cls.deploy_storage_147_solidity_contract(cls)
        cls.deploy_test_185_solidity_contract(cls)

    def deploy_storage_147_solidity_contract(self):
        compiled_sol = compile_source(STORAGE_SOLIDITY_SOURCE_147)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=storage.bytecode),
            eth_account.key
        )
        print('trx_deploy:', trx_deploy)
        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.storage_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=storage.abi
        )

    def deploy_test_185_solidity_contract(self):
        compiled_sol = compile_source(SOLIDITY_SOURCE_185)
        contract_id, contract_interface = compiled_sol.popitem()
        test_185_solidity_contract = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=test_185_solidity_contract.bytecode),
            eth_account.key
        )
        print('trx_deploy:', trx_deploy)
        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.test_185_solidity_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=test_185_solidity_contract.abi
        )

    @unittest.skip("a.i.")
    def test_call_retrieve_right_after_deploy(self):
        print("\ntest_call_retrieve_right_after_deploy")
        number = self.storage_contract.functions.retrieve().call()
        print('number:', number)
        self.assertEqual(number, 0)

    @unittest.skip("a.i.")
    def test_execute_with_right_nonce(self):
        print("\ntest_execute_with_right_nonce")
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
    def test_execute_with_low_gas(self):
        print("\ntest_execute_with_right_nonce")
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
    def test_execute_with_bad_nonce(self):
        print("\ntest_execute_with_bad_nonce")
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

    # @unittest.skip("a.i.")
    def test_06_execute_long_transaction(self):
        print("\ntest_06_execute_long_transaction")
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

        times_to_calculate = 1000
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
        self.assertEqual(value.hex(), 'a6bfac152f9071fbc21a73ca991a28898ec14f4df54c01cad49daf05d4012b4c')
        print('times_to_calculate:', times_to_calculate)
        print('time_duration:', time_duration)


if __name__ == '__main__':
    unittest.main()
