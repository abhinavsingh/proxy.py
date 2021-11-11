import unittest
import os
import solcx

import eth_account
import eth_typing
import eth_utils
from eth_account.account import LocalAccount

from web3 import Web3, eth as web3_eth
from solana.rpc.api import Client as SolanaClient

from ..plugin.solana_rest_api import EthereumModel
from ..plugin.solana_rest_api_tools import get_token_balance_gwei, EthereumAddress, ether2program


class TestAirdroppingEthAccounts(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._EVM_LOADER_ID = os.environ.get("EVM_LOADER")
        new_user_airdrop_amount = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))
        cls._EXPECTED_BALANCE_WEI = eth_utils.to_wei(new_user_airdrop_amount, 'ether')
        cls._MINIMAL_GAS_PRICE = int(os.environ.get("MINIMAL_GAS_PRICE", 1)) * eth_utils.denoms.gwei

        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        cls._web3 = Web3(Web3.HTTPProvider(proxy_url))
        solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
        cls._solana_client = SolanaClient(solana_url)
        cls._host_solana_account = EthereumModel.get_solana_account()

    def test_airdrop_on_get_balance(self):
        account: LocalAccount = eth_account.account.Account.create()
        block_number: eth_typing.BlockNumber = self._web3.eth.get_block_number()
        actual_balance_wei = self._web3.eth.get_balance(account.address, block_identifier=block_number)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, actual_balance_wei)

    def test_airdrop_on_deploy(self):
        contract_owner: LocalAccount = self._web3.eth.account.create()
        contract = self._compile_and_deploy_contract(contract_owner, self._CONTRACT_STORAGE_SOURCE)
        actual_balance_wei = self._get_balance_wei(contract.address)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, actual_balance_wei)

    def test_airdrop_onto_wrapped_new_address(self):
        contract_owner: LocalAccount = self._web3.eth.account.create()
        contract = self._compile_and_deploy_contract(contract_owner, self._WRAPPER_CONTRACT_STORAGE_SOURCE)
        nested_contract_address = contract.functions.getNested().call()
        nested_actual_balance = self._get_balance_wei(nested_contract_address)
        wrapper_actual_balance = self._get_balance_wei(contract.address)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, wrapper_actual_balance)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, nested_actual_balance)

    def _compile_and_deploy_contract(self, contract_owner: LocalAccount, source: str) -> web3_eth.Contract:
        compiled_sol = solcx.compile_source(source)
        contract_id, contract_interface = compiled_sol.popitem()
        contract = self._web3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        nonce = self._web3.eth.get_transaction_count(contract_owner.address)
        chain_id = self._web3.eth.chain_id
        trx_signed = self._web3.eth.account.sign_transaction(
            dict(nonce=nonce, chainId=chain_id, gas=987654321, gasPrice=self._MINIMAL_GAS_PRICE, to='', value=0, data=contract.bytecode),
            contract_owner.key
        )
        trx_hash = self._web3.eth.send_raw_transaction(trx_signed.rawTransaction)
        trx_receipt = self._web3.eth.wait_for_transaction_receipt(trx_hash)
        contract = self._web3.eth.contract(
            address=trx_receipt.contractAddress,
            abi=contract.abi
        )
        return contract

    def _get_balance_wei(self, eth_acc: str) -> int:
        pub_key = self._host_solana_account.public_key()
        token_owner_account, nonce = ether2program(eth_acc, self._EVM_LOADER_ID, pub_key)
        balance, error = get_token_balance_gwei(self._solana_client, token_owner_account, EthereumAddress(eth_acc))
        self.assertIsNone(error)
        self.assertIsNotNone(balance)
        self.assertIsInstance(balance, int)
        return balance * eth_utils.denoms.gwei

    _CONTRACT_STORAGE_SOURCE = '''
        // SPDX-License-Identifier: GPL-3.0
        pragma solidity >=0.7.0 <0.9.0;
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

    _WRAPPER_CONTRACT_STORAGE_SOURCE = '''
        // SPDX-License-Identifier: GPL-3.0
        pragma solidity >=0.7.0 <0.9.0;
        contract Wrapper {
            address private nested_address;
            constructor() {
                Nested nested = new Nested();
                nested_address = address(nested);
            }
            function getNested() public view returns (address) {
                return nested_address;
            }
        }
        contract Nested {}
    '''
