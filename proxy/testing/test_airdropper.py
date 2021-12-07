import unittest
from proxy.testing.mock_server import MockServer
from proxy.indexer.airdropper import Airdropper
from proxy.indexer.sql_dict import SQLDict
import time
from flask import request, Response
from unittest.mock import MagicMock, patch, call, ANY
import itertools
from proxy.testing.transactions import pre_token_airdrop_trx1, pre_token_airdrop_trx2,\
    create_sol_acc_and_airdrop_trx, wrapper_whitelist, evm_loader_addr, token_airdrop_address1, \
    token_airdrop_address2, token_airdrop_address3

class MockFaucet(MockServer):
    def __init__(self, port):
        super().__init__(port)
        self.request_eth_token_mock = MagicMock()
        self.request_eth_token_mock.side_effect = itertools.repeat({})
        self.add_url_rule("/request_eth_token", callback=self.request_eth_token, methods=['POST'])

    def request_eth_token(self):
        req = request.get_json()
        return self.request_eth_token_mock(req)


def create_signature_for_address(signature: str):
    return {
        'blockTime': 1638177745, # not make sense
        'confirmationStatus': 'finalized',
        'err': None,
        'memo': None,
        'signature': signature,
        'slot': 9748200 # not make sense
    }


def create_get_signatures_for_address(signatures: list):
    return {
        'jsonrpc': '2.0',
        'result': [ create_signature_for_address(sign) for sign in signatures ],
        'id': 1
    }


class Test_Airdropper(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("testing indexer in airdropper mode")
        cls.address = 'localhost'
        cls.faucet_port = 3333
        cls.airdrop_amount = 10

        cls.faucet = MockFaucet(cls.faucet_port)
        cls.faucet.start()
        time.sleep(0.2)

        cls.evm_loader_id = evm_loader_addr
        cls.wrapper_whitelist = wrapper_whitelist
        cls.airdropper = Airdropper(f'http://{cls.address}:8899',
                                    cls.evm_loader_id,
                                    f'http://{cls.address}:{cls.faucet_port}',
                                    cls.wrapper_whitelist,
                                    cls.airdrop_amount,
                                    'INFO')


    @classmethod
    def tearDownClass(cls) -> None:
        cls.faucet.shutdown_server()
        cls.faucet.join()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_success_process_trx_with_one_airdrop(self,
                                                  mock_sql_dict_contains,
                                                  mock_sql_dict_setitem):
        print("\n\nShould airdrop to new address - one target in transaction")
        mock_sql_dict_contains.side_effect = [False] # new eth address
        self.faucet.request_eth_token_mock.side_effect = [Response("{}", status=200, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_sql_dict_setitem.assert_has_calls([call(token_airdrop_address1, ANY)])
        json_req = {'wallet': token_airdrop_address1, 'amount': self.airdrop_amount}
        self.faucet.request_eth_token_mock.assert_called_once_with(json_req)
        self.faucet.request_eth_token_mock.reset_mock()


    @patch.object(Airdropper, '_is_allowed_wrapper_contract')
    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_failed_airdrop_contract_not_in_whitelist(self,
                                                      mock_sql_dict_contains,
                                                      mock_sql_dict_setitem,
                                                      mock_is_allowed_contract):
        print("\n\nShould not airdrop for contract that is not in whitelist")
        mock_is_allowed_contract.side_effect = [False]
        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_is_allowed_contract.assert_called_once()
        mock_sql_dict_contains.assert_not_called()
        mock_sql_dict_setitem.assert_not_called()
        self.faucet.request_eth_token_mock.assert_not_called()
        self.faucet.request_eth_token_mock.reset_mock()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_faucet_failure(self,
                            mock_sql_dict_contains,
                            mock_sql_dict_setitem):
        print("\n\nShould not add address to processed list due to faucet error")
        mock_sql_dict_contains.side_effect = [False]  # new eth address
        self.faucet.request_eth_token_mock.side_effect = [Response("{}", status=400, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_sql_dict_setitem.assert_not_called()
        json_req = {'wallet': token_airdrop_address1, 'amount': self.airdrop_amount}
        self.faucet.request_eth_token_mock.assert_called_once_with(json_req)
        self.faucet.request_eth_token_mock.reset_mock()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_process_trx_with_one_airdrop_for_already_processed_address(self,
                                                                        mock_sql_dict_contains,
                                                                        mock_sql_dict_setitem):
        print("\n\nShould not airdrop to repeated address")
        mock_sql_dict_contains.side_effect = [True]  # eth address processed later

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_sql_dict_setitem.assert_not_called()
        self.faucet.request_eth_token_mock.assert_not_called()
        self.faucet.request_eth_token_mock.reset_mock()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_complex_transation(self,
                                mock_sql_dict_contains,
                                mock_sql_dict_setitem):
        print("\n\nShould airdrop to several targets in one transaction")
        mock_sql_dict_contains.side_effect = [False, False] # both targets are new
        self.faucet.request_eth_token_mock.side_effect = [Response("{}", status=200, mimetype='application/json'),
                                                          Response("{}", status=200, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx2)

        mock_sql_dict_contains.assert_has_calls([call(token_airdrop_address3),
                                                 call(token_airdrop_address2)])
        mock_sql_dict_setitem.assert_has_calls([call(token_airdrop_address3, ANY),
                                                call(token_airdrop_address2, ANY)])
        json_req1 = {'wallet': token_airdrop_address2, 'amount': self.airdrop_amount}
        json_req2 = {'wallet': token_airdrop_address3, 'amount': self.airdrop_amount}
        self.faucet.request_eth_token_mock.assert_has_calls([call(json_req2), call(json_req1)])
        self.faucet.request_eth_token_mock.reset_mock()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_no_airdrop_instructions(self,
                                     mock_sql_dict_contains,
                                     mock_sql_dict_setitem):
        print("\n\nShould not airdrop when instructions are inconsistent")
        self.airdropper.process_trx_airdropper_mode(create_sol_acc_and_airdrop_trx)

        mock_sql_dict_contains.assert_not_called()
        mock_sql_dict_setitem.assert_not_called()
        self.faucet.request_eth_token_mock.assert_not_called()
        self.faucet.request_eth_token_mock.reset_mock()

