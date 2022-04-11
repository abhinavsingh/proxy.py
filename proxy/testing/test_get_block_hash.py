from typing import List
import unittest
import os

import rlp
from web3 import Web3
from web3.types import TxParams
from .testing_helpers import request_airdrop
from solcx import compile_source

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create()
proxy.eth.default_account = eth_account.address


BLOCK_HASH_SOLIDITY_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract BlockHashTest {
    event Added(bytes32 hash);

    function getCurrentValues() public payable returns (bytes32) {
        uint blockNumber = block.number;
        bytes32 blockHashNow = blockhash(blockNumber);
        emit Added(blockHashNow);
        return blockHashNow;
    }

    function getValues(uint number) public payable returns (bytes32) {
        bytes32 blockHash = blockhash(number);
        emit Added(blockHash);
        return blockHash;
    }
}
'''


class Test_get_block_hash(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\nTest_get_block_hash\n")
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        request_airdrop(eth_account.address)

        cls.deploy_contract(cls)

    def deploy_contract(self):
        compiled_sol = compile_source(BLOCK_HASH_SOLIDITY_SOURCE)
        _contract_id, contract_interface = compiled_sol.popitem()
        storage = proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
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

    def commit_getCurrentValues(self) -> List[str]:
        print("getCurrentValues()")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx = self.storage_contract.functions.getCurrentValues().buildTransaction({'nonce': right_nonce})
        return self.sent_tx_get_log(trx)

    def commit_getValues(self, block_num: int) -> List[str]:
        print(f"getValues({block_num})")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx = self.storage_contract.functions.getValues(block_num).buildTransaction({'nonce': right_nonce})
        return self.sent_tx_get_log(trx)

    @staticmethod
    def sent_tx_get_log(trx: TxParams) -> List[str]:
        trx_signed = proxy.eth.account.sign_transaction(trx, eth_account.key)
        trx_hash = proxy.eth.send_raw_transaction(trx_signed.rawTransaction)
        trx_receipt = proxy.eth.wait_for_transaction_receipt(trx_hash)
        topics = []
        print('trx_receipt:', trx_receipt)
        for log in trx_receipt['logs']:
            topics.append(log['data'])
        return topics

    def test_getCurrentBlockHash(self):
        print("\ntest_getCurrentBlockHash")
        logs = self.commit_getCurrentValues()
        self.assertEqual(logs[0], '0x0000000000000000000000000000000000000000000000000000000000000000')

    def test_getBlockHashFromHistory(self):
        print("\ntest_getBlockHashFromHistory")
        current_block_number = proxy.eth.block_number
        print(current_block_number)
        block_number_history = int(str(current_block_number), 0) - 50
        block_hash_history = proxy.eth.get_block(block_number_history)['hash'].hex()
        logs = self.commit_getValues(block_number_history)
        print(block_hash_history)
        print(logs)
        self.assertEqual(logs[0], block_hash_history)

if __name__ == '__main__':
    unittest.main()
