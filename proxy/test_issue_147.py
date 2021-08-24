import unittest
import os
from web3 import Web3
from solcx import install_solc

# install_solc(version='latest')
install_solc(version='0.7.0')
from solcx import compile_source

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


class Test147(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nhttps://github.com/neonlabsorg/proxy-model.py/issues/147")
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
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

        cls.storage_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=storage.abi
        )

    def test_call_retrieve_right_after_deploy(self):
        number = self.storage_contract.functions.retrieve().call()
        print('number:', number)
        self.assertEqual(number, 0)

    def test_execute_with_right_nonce(self):
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

    def test_execute_with_bad_nonce(self):
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


if __name__ == '__main__':
    unittest.main()
