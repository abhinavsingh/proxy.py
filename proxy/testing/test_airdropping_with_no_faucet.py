import unittest
import os

import eth_account
import eth_typing
import eth_utils

from eth_account.account import LocalAccount
from solana.rpc.api import Client as SolanaClient

from ..plugin.solana_rest_api_tools import get_token_balance_gwei, ether2program
from .testing_helpers import SolidityContractDeployer


class TestAirdroppingEthAccounts(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        new_user_airdrop_amount = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))
        cls._EXPECTED_BALANCE_WEI = eth_utils.to_wei(new_user_airdrop_amount, 'ether')

        cls._contract_deployer = SolidityContractDeployer()
        cls._web3 = cls._contract_deployer.web3

        solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
        cls._solana_client = SolanaClient(solana_url)

    def test_airdrop_on_get_balance(self):
        account: LocalAccount = eth_account.account.Account.create()
        block_number: eth_typing.BlockNumber = self._web3.eth.get_block_number()
        actual_balance_wei = self._web3.eth.get_balance(account.address, block_identifier=block_number)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, actual_balance_wei)

    def test_airdrop_on_deploy(self):
        contract_owner: LocalAccount = self._web3.eth.account.create()
        contract = self._contract_deployer.compile_and_deploy_contract(contract_owner, self._CONTRACT_STORAGE_SOURCE)
        actual_balance_wei = self._get_balance_wei(contract.address)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, actual_balance_wei)

    def test_airdrop_onto_wrapped_new_address(self):
        contract_owner: LocalAccount = self._web3.eth.account.create()
        contract = self._contract_deployer.compile_and_deploy_contract(contract_owner, self._WRAPPER_CONTRACT_STORAGE_SOURCE)
        nested_contract_address = contract.functions.getNested().call()
        nested_actual_balance = self._get_balance_wei(nested_contract_address)
        wrapper_actual_balance = self._get_balance_wei(contract.address)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, wrapper_actual_balance)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, nested_actual_balance)

    def test_airdrop_on_deploy_estimation(self):
        owner_eth_account: LocalAccount = self._web3.eth.account.create()
        compiled_info = self._contract_deployer.compile_contract(self._CONTRACT_STORAGE_SOURCE)
        contract_data = compiled_info.contract_interface.get("bin")
        self.assertIsNotNone(contract_data)
        self._web3.eth.estimate_gas({"from": owner_eth_account.address, "data": contract_data})
        owner_balance = self._get_balance_wei(owner_eth_account.address)
        self.assertEqual(self._EXPECTED_BALANCE_WEI, owner_balance)

    def _get_balance_wei(self, eth_account: str) -> int:
        token_owner_account, nonce = ether2program(eth_account)
        balance = get_token_balance_gwei(self._solana_client, token_owner_account)
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
