import unittest
import os

import rlp
from web3 import Web3
from .testing_helpers import request_airdrop
from solcx import compile_source

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create()
proxy.eth.default_account = eth_account.address


STORAGE_SOLIDITY_SOURCE = '''
pragma solidity >=0.7.0 <0.9.0;

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



class Test_createAccountBlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/147")
        request_airdrop(eth_account.address)

        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        print('balance:', proxy.eth.get_balance(eth_account.address))

        # Create caller account in NeonEVM
        cls.deploy_contract(cls)

    def deploy_contract(self):
        compiled_sol = compile_source(STORAGE_SOLIDITY_SOURCE)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to='',
            value=0,
            data=storage.bytecode),
            eth_account.key
        )

        trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        return proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)

    def transfer(self, target_account, value):
        trx_transfer = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to=bytes(target_account),
            value=value),
            eth_account.key
        )

        transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
        return proxy.eth.wait_for_transaction_receipt(transfer_hash)

    def test_blockAccount(self):
        nonce = proxy.eth.get_transaction_count(eth_account.address)
        expected_contract_address = proxy.keccak(rlp.encode((bytes.fromhex(eth_account.address[2:]), nonce + 1)))[-20:]

        # Create expected contract account
        transfer_receipt = self.transfer(expected_contract_address, 1_000_000_000)
        self.assertEqual(transfer_receipt["status"], 1)

        # Try to deploy to expected contract account
        deploy_receipt = self.deploy_contract()
        self.assertEqual(deploy_receipt["status"], 1)


if __name__ == '__main__':
    unittest.main()
