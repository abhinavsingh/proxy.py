import unittest
import eth_account
import eth_typing
import eth_utils
import os
from web3 import Web3
import solcx
import logging

NEW_USER_AIRDROP_AMOUNT = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))


class TestAirdroppingEthAccounts(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        cls.proxy = Web3(Web3.HTTPProvider(proxy_url))

    def test_airdrop_on_get_balance(self):
        account: eth_account.account.LocalAccount = eth_account.account.Account.create()
        block_number: eth_typing.BlockNumber = self.proxy.eth.get_block_number()
        actual_balance_wei = self.proxy.eth.get_balance(account.address, block_identifier=block_number)
        expected_balance_wei = eth_utils.to_wei(NEW_USER_AIRDROP_AMOUNT, 'ether')
        self.assertEqual(expected_balance_wei, actual_balance_wei)

    def test_airdrop_on_deploy(self):
        contract_owner: eth_account.account.LocalAccount = self.proxy.eth.account.create()
        compiled_sol = solcx.compile_source(self._CONTRACT_STORAGE_SOURCE)
        contract_id, contract_interface = compiled_sol.popitem()
        storage = self.proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        nonce = self.proxy.eth.get_transaction_count(contract_owner.address)
        chain_id = self.proxy.eth.chain_id
        trx_signed = self.proxy.eth.account.sign_transaction(
            dict(nonce=nonce, chainId=chain_id, gas=987654321, gasPrice=0, to='', value=0, data=storage.bytecode),
            contract_owner.key
        )
        trx_hash = self.proxy.eth.send_raw_transaction(trx_signed.rawTransaction)
        trx_receipt = self.proxy.eth.wait_for_transaction_receipt(trx_hash)
        storage_contract = self.proxy.eth.contract(
            address=trx_receipt.contractAddress,
            abi=storage.abi
        )
        actual_balance_wei = self.proxy.eth.get_balance(storage_contract.address, block_identifier="latest")
        expected_balance_wei = eth_utils.to_wei(NEW_USER_AIRDROP_AMOUNT, 'ether')

        owner_balance = self.proxy.eth.get_balance(contract_owner.address, block_identifier="latest")

        self.assertEqual(expected_balance_wei, owner_balance)
        self.assertEqual(expected_balance_wei, actual_balance_wei)

    _CONTRACT_STORAGE_SOURCE = '''pragma solidity >=0.7.0 <0.9.0;
        contract Storage {
            uint256 number;
            function store(uint256 num) public {
                number = num;
            }
            function retrieve() public view returns (uint256) {
                return number;
            }
        }
    '''

