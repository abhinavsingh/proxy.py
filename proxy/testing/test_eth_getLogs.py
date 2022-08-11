import unittest
import os
from web3 import Web3
from solcx import compile_source

from proxy.testing.testing_helpers import request_airdrop

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/210'
EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create(SEED)
proxy.eth.default_account = eth_account.address

TEST_EVENT_SOURCE_210 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.5.12;

contract ReturnsEvents {
    event Added(uint8 sum);

    function addNoReturn(uint8 x, uint8 y) public {
        x + y;
    }

    function addReturn(uint8 x, uint8 y) public returns(uint8) {
        return x + y;
    }

    function addReturnEvent(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum =x+y;

        emit Added(sum);
        return sum;
    }

    function addReturnEventTwice(uint8 x, uint8 y) public returns(uint8) {
        uint8 sum = x + y;
        emit Added(sum);
        sum += y;
        emit Added(sum);
        return sum;
    }
}
'''


class Test_eth_getLogs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("\n\n")
        print(SEED)
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        request_airdrop(eth_account.address)

        cls.block_hashes = []
        cls.topics = []
        cls.block_numbers = []

        cls.block_hashes_no_event = []
        cls.block_numbers_no_event = []

        cls.deploy_contract(cls)
        cls.commit_transactions(cls)

        print(cls.block_hashes)
        print(cls.topics)
        print(cls.block_numbers)
        print(cls.block_hashes_no_event)
        print(cls.block_numbers_no_event)

    def deploy_contract(self):
        compiled_sol = compile_source(TEST_EVENT_SOURCE_210)
        contract_id, contract_interface = compiled_sol.popitem()
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

    def commit_transactions(self):
        self.commit_one_event_trx(self, 1, 2)
        self.commit_one_event_trx(self, 2, 3)
        self.commit_two_event_trx(self, 3, 4)
        self.commit_two_event_trx(self, 5, 6)
        self.commit_no_event_trx(self, 7, 8)
        self.commit_no_event_trx(self, 9, 0)

    def commit_one_event_trx(self, x, y) -> None:
        print(f"\ncommit_one_event_trx. x: {x}, y: {y}")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.addReturnEvent(x, y).buildTransaction({'nonce': right_nonce})
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)

        print('trx_store_receipt:', trx_store_receipt)
        self.block_hashes.append(trx_store_receipt['blockHash'].hex())
        self.block_numbers.append(hex(trx_store_receipt['blockNumber']))
        for log in trx_store_receipt['logs']:
            for topic in log['topics']:
                self.topics.append(topic.hex())

    def commit_two_event_trx(self, x, y) -> None:
        print(f"\ncommit_two_event_trx. x: {x}, y: {y}")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.addReturnEventTwice(x, y).buildTransaction({'nonce': right_nonce})
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)

        print('trx_store_receipt:', trx_store_receipt)
        self.block_hashes.append(trx_store_receipt['blockHash'].hex())
        self.block_numbers.append(hex(trx_store_receipt['blockNumber']))
        for log in trx_store_receipt['logs']:
            for topic in log['topics']:
                self.topics.append(topic.hex())

    def commit_no_event_trx(self, x, y) -> None:
        print("\ncommit_no_event_trx")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.addReturn(x, y).buildTransaction({'nonce': right_nonce})
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)

        print('trx_store_receipt:', trx_store_receipt)
        self.block_hashes_no_event.append(trx_store_receipt['blockHash'].hex())
        self.block_numbers_no_event.append(hex(trx_store_receipt['blockNumber']))

    def test_get_logs_by_blockHash(self):
        print("\ntest_get_logs_by_blockHash")
        receipts = proxy.eth.get_logs({
            'blockHash': self.block_hashes[0],
            'address': self.storage_contract.address
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 1)

    def test_get_no_logs_by_blockHash(self):
        print("\ntest_get_no_logs_by_blockHash")
        receipts = proxy.eth.get_logs({
            'blockHash': self.block_hashes_no_event[0],
            'address': self.storage_contract.address
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 0)

    def test_get_logs_by_fromBlock(self):
        print("\ntest_get_logs_by_fromBlock")
        receipts = proxy.eth.get_logs({
            'fromBlock': self.block_numbers[2],
            'address': self.storage_contract.address
        })
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 4)

    def test_get_logs_complex_request(self):
        print("\ntest_get_logs_complex_request")
        receipts = proxy.eth.get_logs({'fromBlock': 0,
                                       'toBlock': 'latest',
                                       'address': self.storage_contract.address,
                                       'topics': self.topics})
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 6)

    def test_get_logs_by_address(self):
        print("\ntest_get_logs_by_address")
        receipts = proxy.eth.get_logs({'address': self.storage_contract.address})
        print('receipts: ', receipts)
        self.assertEqual(len(receipts), 6)


if __name__ == '__main__':
    unittest.main()
