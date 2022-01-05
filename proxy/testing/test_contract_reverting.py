import unittest
import os

import eth_utils
from web3 import exceptions as web3_exceptions
from solana.rpc.api import Client as SolanaClient
from eth_account.account import LocalAccount

from .testing_helpers import SolidityContractDeployer
from ..common_neon.emulator_interactor import decode_revert_message


class TestContractReverting(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._contract_deployer = SolidityContractDeployer()
        cls._web3 = cls._contract_deployer.web3

        new_user_airdrop_amount = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))
        cls._EXPECTED_BALANCE_WEI = eth_utils.to_wei(new_user_airdrop_amount, 'ether')

        solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
        cls._solana_client = SolanaClient(solana_url)

    def test_revert_message_decoding(self):
        revert_message = decode_revert_message(self._STRING_BASED_REVERT_DATA)
        self.assertEqual(revert_message, "Not enough Ether provided.")

    _STRING_BASED_REVERT_DATA = "08c379a0" \
                                "0000000000000000000000000000000000000000000000000000000000000020" \
                                "000000000000000000000000000000000000000000000000000000000000001a" \
                                "4e6f7420656e6f7567682045746865722070726f76696465642e000000000000"

    def test_constructor_raises_string_based_error(self):
        compiled_info = self._contract_deployer.compile_contract(self._CONTRACT_CONSTRUCTOR_STRING_BASED_REVERT)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            compiled_info.contract.constructor([]).buildTransaction()
        self.assertEqual("execution reverted: ListConstructable: empty list", str(cm.exception))

    _CONTRACT_CONSTRUCTOR_STRING_BASED_REVERT = '''
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            constructor(uint256[] memory vector_) payable {
                require(vector_.length > 0, "ListConstructable: empty list");
            }
        }
    '''

    def test_constructor_raises_no_argument_error(self):
        compiled_info = self._contract_deployer.compile_contract(self._CONTRACT_CONSTRUCTOR_REVERT)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            compiled_info.contract.constructor([]).buildTransaction()
        self.assertEqual("execution reverted", str(cm.exception))

    _CONTRACT_CONSTRUCTOR_REVERT = '''
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            constructor(uint256[] memory vector_) payable {
                require(vector_.length > 0);
            }
        }
    '''

    def test_method_raises_string_based_error(self):
        contract_owner: LocalAccount = self._web3.eth.account.create()
        contract = self._contract_deployer.compile_and_deploy_contract(contract_owner, self._CONTRACT_METHOD_STRING_BASED_REVERT)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            contract.functions.do_string_based_revert().call()
        self.assertEqual("execution reverted: Predefined revert happened", str(cm.exception))

    def test_method_raises_trivial_error(self):
        contract_owner: LocalAccount = self._web3.eth.account.create()
        contract = self._contract_deployer.compile_and_deploy_contract(contract_owner, self._CONTRACT_METHOD_STRING_BASED_REVERT)
        with self.assertRaises(web3_exceptions.ContractLogicError) as cm:
            contract.functions.do_trivial_revert().call()
        self.assertEqual("execution reverted", str(cm.exception))

    _CONTRACT_METHOD_STRING_BASED_REVERT = '''
        pragma solidity >=0.7.0 <0.9.0;
        contract ArrConstructable {
            function do_string_based_revert() public view returns (uint256) {
                require(false, "Predefined revert happened");
            }
            function do_trivial_revert() public view returns (uint256) {
                require(false);
            }
        }
    '''

