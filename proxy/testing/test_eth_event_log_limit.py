import unittest
import os
from web3 import Web3
from solcx import compile_source

from proxy.testing.testing_helpers import request_airdrop
from proxy.common_neon import environment_data

SEED = 'https://github.com/neonlabsorg/proxy-model.py/issues/812'
EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create(SEED)
proxy.eth.default_account = eth_account.address

TEST_EVENT_SOURCE_812 = '''
// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0;

contract GenerateEvents {
    event Frob(bytes);

    function frobnicate(uint size, bytes1 char) public {
        bytes memory s = new bytes(size);
        for (uint i = 0; i < size; i++) {
            s[i] = char;
        }
        emit Frob(s);
    }
}
'''

class Test_eth_event_log_limit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\n")
        print(SEED)
        print('eth_account.address:', eth_account.address)
        print('eth_account.key:', eth_account.key.hex())
        request_airdrop(eth_account.address)

        cls.block_hashes = []
        cls.block_numbers = []
        cls.topics = []

        cls.deploy_contract(cls)
        cls.commit_transactions(cls)

        print(cls.block_hashes)
        print(cls.block_numbers)
        print(cls.topics)

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def deploy_contract(self):
        compiled_sol = compile_source(TEST_EVENT_SOURCE_812)
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
        self.commit_event_trx(self, 1000, 41)
        self.commit_event_trx(self, 2000, 42)
        self.commit_event_trx(self, 3000, 43)
        pass

    def commit_event_trx(self, event_size: int, char: int) -> None:
        print("\ncommit_event_trx(", event_size, char, ")")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.frobnicate(event_size, bytes([char])).buildTransaction({'nonce': right_nonce})
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)

        print('trx_store_receipt:', trx_store_receipt)
        self.block_hashes.append(trx_store_receipt['blockHash'].hex())
        self.block_numbers.append(hex(trx_store_receipt['blockNumber']))
        for log in trx_store_receipt['logs']:
            for topic in log['topics']:
                self.topics.append(topic.hex())

    def test_get_logs_by_blockHash(self):
        print("\ntest_get_logs_by_blockHash")
        receipts = proxy.eth.get_logs({'blockHash': self.block_hashes[0]})
        print('receipts[0]: ', receipts)
        receipts = proxy.eth.get_logs({'blockHash': self.block_hashes[1]})
        print('receipts[1]: ', receipts)
        receipts = proxy.eth.get_logs({'blockHash': self.block_hashes[2]})
        print('receipts[2]: ', receipts)
        pass

if __name__ == '__main__':
    unittest.main()
