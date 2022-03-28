import unittest
import os
import json

import eth_utils
from web3 import Web3
from .testing_helpers import request_airdrop
from solcx import compile_source


EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
proxy = Web3(Web3.HTTPProvider(proxy_url))
eth_account = proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/147')
proxy.eth.default_account = eth_account.address

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
        request_airdrop(eth_account.address)
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
            gasPrice=2000000000,
            to='',
            value=0,
            data=storage.bytecode),
            eth_account.key
        )
        print('trx_deploy:', trx_deploy)
        self.trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
        print('trx_deploy_hash:', self.trx_deploy_hash.hex())
        trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(self.trx_deploy_hash)
        print('trx_deploy_receipt:', trx_deploy_receipt)

        self.deploy_block_hash = trx_deploy_receipt['blockHash']
        self.deploy_block_num = trx_deploy_receipt['blockNumber']
        print('deploy_block_hash:', self.deploy_block_hash)
        print('deploy_block_num:', self.deploy_block_num)

        self.storage_contract = proxy.eth.contract(
            address=trx_deploy_receipt.contractAddress,
            abi=storage.abi
        )

    def deploy_test_185_solidity_contract(self):
        compiled_sol = compile_source(SOLIDITY_SOURCE_185)
        contract_id, contract_interface = compiled_sol.popitem()
        test_185_solidity_contract = proxy.eth.contract(
            abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        trx_deploy = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
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

    # @unittest.skip("a.i.")
    def test_check_get_block_by_hash(self):
        print("\ntest_check_get_block_by_hash")
        block = proxy.eth.get_block(self.deploy_block_hash, full_transactions=True)
        print('block:', block)
        has_tx = False
        for tx in block['transactions']:
            if tx['hash'] == self.trx_deploy_hash:
                has_tx = True
                break
        self.assertTrue(has_tx)

    # @unittest.skip("a.i.")
    def test_check_get_block_by_number(self):
        print("\ntest_check_get_block_by_number")
        block = proxy.eth.get_block(int(self.deploy_block_num))
        print('block:', block)
        has_tx = False
        for tx in block['transactions']:
            if tx == self.trx_deploy_hash:
                has_tx = True
                break
        self.assertTrue(has_tx)

    # @unittest.skip("a.i.")
    def test_01_call_retrieve_right_after_deploy(self):
        print("\ntest_01_call_retrieve_right_after_deploy")
        number = self.storage_contract.functions.retrieve().call()
        print('number:', number)
        self.assertEqual(number, 0)

    # @unittest.skip("a.i.")
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

    # @unittest.skip("a.i.")
    def test_03_execute_with_low_gas(self):
        print("\ntest_03_execute_with_low_gas")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.store(148).buildTransaction({
            'nonce': right_nonce,
            'gasPrice': 1000000000,
            'gas': 0})
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
            response = json.loads(str(e).replace('\'', '\"').replace('None', 'null'))
            print('response:', response)
            print('code:', response['code'])
            self.assertEqual(response['code'], -32000)
            print('message:', response['message'])
            message = 'gas limit reached'
            self.assertEqual(response['message'][:len(message)], message)

    # @unittest.skip("a.i.")
    def test_04_execute_with_bad_nonce(self):
        test_nonce_list = [
            ('grade_up_one', 1, 'nonce too high:'),
            ('grade_down_one', -1, 'nonce too low: ')
        ]
        for name, offset, message in test_nonce_list:
            with self.subTest(name=name):
                print("\ntest_04_execute_with_bad_nonce {} offsets".format(offset))
                bad_nonce = offset + proxy.eth.get_transaction_count(proxy.eth.default_account)
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
                    response = json.loads(str(e).replace('\'', '\"').replace('None', 'null'))
                    print('response:', response)
                    print('code:', response['code'])
                    self.assertEqual(response['code'], -32002)
                    print('message:', response['message'])
                    self.assertEqual(response['message'][:len(message)], message)

    # @unittest.skip("a.i.")
    def test_05_transfer_one_gwei(self):
        print("\ntest_05_transfer_one_gwei")

        eth_account_alice = proxy.eth.account.create('alice')
        eth_account_bob = proxy.eth.account.create('bob')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)
        request_airdrop(eth_account_alice.address)
        request_airdrop(eth_account_bob.address)

        if True:
            print("add funds to alice and bob")

            print("alice")
            trx_transfer = proxy.eth.account.sign_transaction(dict(
                nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=1000000000,
                to=eth_account_alice.address,
                value=eth_utils.denoms.gwei),
                eth_account.key
            )

            print('trx_transfer:', trx_transfer)
            trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
            print('trx_transfer_hash:', trx_transfer_hash.hex())
            trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
            print('trx_transfer_receipt:', trx_transfer_receipt)

            print("bob")
            trx_transfer = proxy.eth.account.sign_transaction(dict(
                nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=1000000000,
                to=eth_account_bob.address,
                value=eth_utils.denoms.gwei),
                eth_account.key
            )

            print('trx_transfer:', trx_transfer)
            trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
            print('trx_transfer_hash:', trx_transfer_hash.hex())
            trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
            print('trx_transfer_receipt:', trx_transfer_receipt)

        alice_balance_before_transfer = proxy.eth.get_balance(eth_account_alice.address)
        bob_balance_before_transfer = proxy.eth.get_balance(eth_account_bob.address)
        print('alice_balance_before_transfer:', alice_balance_before_transfer)
        print('bob_balance_before_transfer:', bob_balance_before_transfer)
        print('one_gwei:', eth_utils.denoms.gwei)

        trx_transfer = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(eth_account_alice.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to=eth_account_bob.address,
            value=eth_utils.denoms.gwei),
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
        self.assertLessEqual(alice_balance_after_transfer, alice_balance_before_transfer - eth_utils.denoms.gwei)
        self.assertEqual(bob_balance_after_transfer, bob_balance_before_transfer + eth_utils.denoms.gwei)

    # @unittest.skip("a.i.")
    def test_06_transfer_one_and_a_half_gweis(self):
        print("\ntest_06_transfer_one_and_a_half_gweis")

        eth_account_alice = proxy.eth.account.create('alice')
        eth_account_bob = proxy.eth.account.create('bob')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)
        request_airdrop(eth_account_alice.address)
        request_airdrop(eth_account_bob.address)

        if True:
            print("add funds to alice and bob")

            print("alice")
            trx_transfer = proxy.eth.account.sign_transaction(dict(
                nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=1000000000,
                to=eth_account_alice.address,
                value=2 * eth_utils.denoms.gwei),
                eth_account.key
            )

            print('trx_transfer:', trx_transfer)
            trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
            print('trx_transfer_hash:', trx_transfer_hash.hex())
            trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
            print('trx_transfer_receipt:', trx_transfer_receipt)

            print("bob")
            trx_transfer = proxy.eth.account.sign_transaction(dict(
                nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
                chainId=proxy.eth.chain_id,
                gas=987654321,
                gasPrice=1000000000,
                to=eth_account_bob.address,
                value=2 * eth_utils.denoms.gwei),
                eth_account.key
            )

            print('trx_transfer:', trx_transfer)
            trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
            print('trx_transfer_hash:', trx_transfer_hash.hex())
            trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
            print('trx_transfer_receipt:', trx_transfer_receipt)

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
            gasPrice=1000000000,
            to=eth_account_bob.address,
            value=one_and_a_half_gweis),
            eth_account_alice.key
        )

        print('trx_transfer:', trx_transfer)
        trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
        print('trx_transfer_hash:', trx_transfer_hash.hex())
        trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
        print('trx_transfer_receipt:', trx_transfer_receipt)

        gas_cost = trx_transfer_receipt['gasUsed'] * 1000000000
        print('gas_cost:', gas_cost)

        alice_balance_after_transfer = proxy.eth.get_balance(eth_account_alice.address)
        bob_balance_after_transfer = proxy.eth.get_balance(eth_account_bob.address)
        print('alice_balance_after_transfer:', alice_balance_after_transfer)
        print('bob_balance_after_transfer:', bob_balance_after_transfer)
        self.assertEqual(alice_balance_after_transfer, alice_balance_before_transfer - one_and_a_half_gweis - gas_cost)
        self.assertEqual(bob_balance_after_transfer, bob_balance_before_transfer + one_and_a_half_gweis)

    # @unittest.skip("a.i.")
    def test_07_execute_long_transaction(self):
        print("\ntest_07_execute_long_transaction")
        contract = self.test_185_solidity_contract
        trx_initValue = contract.functions.initValue('185 init value').buildTransaction({
            'nonce': proxy.eth.get_transaction_count(proxy.eth.default_account)})
        print('trx_initValue:', trx_initValue)
        trx_initValue_signed = proxy.eth.account.sign_transaction(trx_initValue, eth_account.key)
        print('trx_initValue_signed:', trx_initValue_signed)
        trx_initValue_hash = proxy.eth.send_raw_transaction(trx_initValue_signed.rawTransaction)
        print('trx_initValue_hash:', trx_initValue_hash.hex())
        trx_initValue_receipt = proxy.eth.wait_for_transaction_receipt(trx_initValue_hash)
        print('trx_initValue_hash_receipt:', trx_initValue_receipt)

        value = contract.functions.getValue().call()
        print('value:', value.hex())
        self.assertEqual(value.hex(), '36fb9ea61aba18555110881836366c8d7701685174abe4926673754580ee26c5')

        from datetime import datetime
        start = datetime.now()

        times_to_calculate = 1000
        trx_calculate = contract.functions.calculateKeccakAndStore(times_to_calculate).buildTransaction({
            'nonce': proxy.eth.get_transaction_count(proxy.eth.default_account)})
        print('trx_calculate:', trx_calculate)
        trx_calculate_signed = proxy.eth.account.sign_transaction(trx_calculate, eth_account.key)
        print('trx_calculate_signed:', trx_calculate_signed)
        trx_calculate_hash = proxy.eth.send_raw_transaction(trx_calculate_signed.rawTransaction)
        print('trx_calculate_hash:', trx_calculate_hash.hex())
        trx_calculate_receipt = proxy.eth.wait_for_transaction_receipt(trx_calculate_hash)
        print('trx_calculate_hash_receipt:', trx_calculate_receipt)

        time_duration = datetime.now() - start

        value = contract.functions.getValue().call()
        print('value:', value.hex())
        self.assertEqual(value.hex(), 'a6bfac152f9071fbc21a73ca991a28898ec14f4df54c01cad49daf05d4012b4c')
        print('times_to_calculate:', times_to_calculate)
        print('time_duration:', time_duration)

    # @unittest.skip("a.i.")
    def test_get_storage_at(self):
        print("\nhttps://github.com/neonlabsorg/proxy-model.py/issues/289")
        right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        value_to_store = 452356
        trx_store = self.storage_contract.functions.store(value_to_store).buildTransaction({'nonce': right_nonce})
        print('trx_store:', trx_store)
        trx_store_signed = proxy.eth.account.sign_transaction(trx_store, eth_account.key)
        print('trx_store_signed:', trx_store_signed)
        trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
        print('trx_store_hash:', trx_store_hash.hex())
        trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)
        print('trx_store_receipt:', trx_store_receipt)

        number_pos = 0
        value_received = proxy.eth.get_storage_at(self.storage_contract.address, number_pos, "latest")
        print('eth_getStorageAt existing address and index => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), value_to_store)

        non_existing_pos = 12
        value_received = proxy.eth.get_storage_at(self.storage_contract.address, non_existing_pos, "latest")
        print('eth_getStorageAt existing address and non-existing index => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), 0)

        non_exising_address = b'\xe1\xda\xb7\xa6\x17\x6f\x87\x68\xF5\x3a\x42\x5f\x29\x61\x73\x60\x5e\xd5\x08\x32'
        value_received = proxy.eth.get_storage_at(non_exising_address, non_existing_pos, "latest")
        print('eth_getStorageAt non-existing address => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), 0)

        not_a_contract_address = proxy.eth.default_account
        value_received = proxy.eth.get_storage_at(not_a_contract_address, 0, "latest")
        print('eth_getStorageAt not_a_contract_address address => ', value_received.hex())
        self.assertEqual(int.from_bytes(value_received, byteorder='big'), 0)

    # @unittest.skip("a.i.")
    def test_08_execute_with_huge_gas(self):
        print("\ntest_08_execute_with_huge_gas_limit")
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        trx_store = self.storage_contract.functions.store(147).buildTransaction({
            'nonce': nonce,
            'gas': 987654321987654321,
            'gasPrice': 1000000000})
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
            response = json.loads(str(e).replace('\'', '\"').replace('None', 'null'))
            print('response:', response)
            print('code:', response['code'])
            self.assertEqual(response['code'], -32000)
            print('message:', response['message'])
            message = 'insufficient funds for gas * price + value'
            self.assertEqual(response['message'][:len(message)], message)

    # @unittest.skip("a.i.")
    def test_09_prior_eip_155(self):
        print("\ntest_09_prior_eip_155")

        eth_test_account = proxy.eth.account.create('eth_test_account')
        print('eth_test_account.address:', eth_test_account.address)

        balance_before_transfer = proxy.eth.get_balance(eth_test_account.address)
        print('balance_before_transfer:', balance_before_transfer)

        print("transfer 1 gwei to eth_test_account")
        trx_transfer = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
            gas=987654321,
            gasPrice=1000000000,
            to=eth_test_account.address,
            value=eth_utils.denoms.gwei),
            eth_account.key
        )

        print('trx_transfer:', trx_transfer)
        trx_transfer_hash = proxy.eth.send_raw_transaction(trx_transfer.rawTransaction)
        print('trx_transfer_hash:', trx_transfer_hash.hex())
        trx_transfer_receipt = proxy.eth.wait_for_transaction_receipt(trx_transfer_hash)
        print('trx_transfer_receipt:', trx_transfer_receipt)

        balance_after_transfer = proxy.eth.get_balance(eth_test_account.address)
        print('balance_after_transfer:', balance_after_transfer)

        self.assertLessEqual(balance_after_transfer, balance_before_transfer + eth_utils.denoms.gwei)

    # @unittest.skip("a.i.")
    def test_10_transfer_not_enough_funds(self):
        print("\ntest_10_transfer_not_enough_funds")

        eth_account_alice = proxy.eth.account.create('alice.whale')
        eth_account_bob = proxy.eth.account.create('bob.carp')
        print('eth_account_alice.address:', eth_account_alice.address)
        print('eth_account_bob.address:', eth_account_bob.address)
        request_airdrop(eth_account_alice.address)

        tx_transfer = proxy.eth.account.sign_transaction(
            {
                "nonce": proxy.eth.get_transaction_count(eth_account_alice.address),
                "chainId": proxy.eth.chain_id,
                "gas": 987654321,
                "gasPrice": 1000000000,
                "to": eth_account_bob.address,
                "value": proxy.eth.get_balance(eth_account_alice.address) + 1,
            },
            eth_account_alice.key
        )
        print('trx_transfer:', tx_transfer)
        try:
            tx_transfer_hash = proxy.eth.send_raw_transaction(tx_transfer.rawTransaction)
            print('trx_transfer_hash:', tx_transfer_hash.hex())
            self.assertTrue(False)
        except Exception as e:
            print('type(e):', type(e))
            print('e:', e)
            response = json.loads(str(e).replace('\'', '\"').replace('None', 'null'))
            print('response:', response)
            print('code:', response['code'])
            self.assertEqual(response['code'], -32000)
            print('message:', response['message'])
            message = 'insufficient funds for transfer'
            self.assertEqual(response['message'][:len(message)], message)


if __name__ == '__main__':
    unittest.main()
