import unittest
import os

import eth_utils
from web3 import Web3
from solcx import compile_source

EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/147')
proxy.eth.default_account = eth_account.address

REVERTING_SOLIDITY_SOURCE_487 = '''
pragma solidity >=0.7.0 <0.9.0;
/**
 * @title Counter
 * @dev Counter & inc/dec value in a variable
 */
contract Reverting {
    function do_revert() public returns (uint256) {
        require(2>3, 'revert');
        return 1;
    }
}
'''


class Test_eth_estimateGas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/487")
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        cls.deploy_counter_487_solidity_contract(cls)

    def deploy_counter_487_solidity_contract(self):
        compiled_sol = compile_source(REVERTING_SOLIDITY_SOURCE_487)
        contract_id, contract_interface = compiled_sol.popitem()
        counter = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=counter.bytecode),
            eth_account.key
        )
        print('trx_deploy:', trx_deploy)
        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.deploy_block_hash = trx_deploy_receipt['blockHash']
        self.deploy_block_num = trx_deploy_receipt['blockNumber']
        print('deploy_block_hash:', self.deploy_block_hash)
        print('deploy_block_num:', self.deploy_block_num)

        self.reverting_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=counter.abi
        )

    # @unittest.skip("a.i.")
    def test_01_check_do_revert(self):
        print("\ntest_check_get_block_by_number")
        try:
            nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
            trx_revert = self.reverting_contract.functions.do_revert().buildTransaction({'nonce': nonce})
            print('trx_revert:', trx_revert)
            trx_estimate_gas_response = proxy.eth.estimate_gas(trx_revert)
            print('trx_estimate_gas_response:', trx_estimate_gas_response)
            self.assertTrue(False)
        except Exception as e:
            print('type(e):', type(e))
            print('e:', e)
            self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
