import unittest
from proxy.testing.mock_server import MockServer
from proxy.indexer.airdropper import Airdropper, AIRDROP_AMOUNT_SOL, NEON_PRICE_USD
from proxy.indexer.sql_dict import SQLDict
from proxy.indexer.price_provider import PriceProvider
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
        self.request_neon_in_galans_mock = MagicMock()
        self.request_neon_in_galans_mock.side_effect = itertools.repeat({})
        self.add_url_rule("/request_neon_in_galans", callback=self.request_neon_in_galans, methods=['POST'])

    def request_neon_in_galans(self):
        req = request.get_json()
        return self.request_neon_in_galans_mock(req)


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
        cls.evm_loader_id = evm_loader_addr
        cls.wrapper_whitelist = wrapper_whitelist
        cls.neon_decimals = 9
        cls.airdropper = Airdropper(f'http://{cls.address}:8899',
                                    cls.evm_loader_id,
                                    f'http://{cls.address}:{cls.faucet_port}',
                                    cls.wrapper_whitelist,
                                    'INFO',
                                    cls.neon_decimals)


    def setUp(self) -> None:
        print(f"\n\n{self._testMethodName}\n{self._testMethodDoc}")
        self.faucet = MockFaucet(self.faucet_port)
        self.faucet.start()
        time.sleep(0.2)


    def tearDown(self) -> None:
        self.faucet.shutdown_server()
        self.faucet.join()


    @patch.object(PriceProvider, 'get_price')
    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_success_process_trx_with_one_airdrop(self,
                                                  mock_sql_dict_contains,
                                                  mock_sql_dict_setitem,
                                                  mock_get_price):
        """
        Should airdrop to new address - one target in transaction
        """
        sol_price = 341
        airdrop_amount = int(pow(10, self.neon_decimals) * (AIRDROP_AMOUNT_SOL * sol_price) / NEON_PRICE_USD)
        mock_get_price.side_effect = [sol_price]
        mock_sql_dict_contains.side_effect = [False] # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=200, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_sql_dict_setitem.assert_has_calls([call(token_airdrop_address1, ANY)])
        mock_get_price.assert_called_once_with('SOL/USD')
        json_req = {'wallet': token_airdrop_address1, 'amount': airdrop_amount}
        self.faucet.request_neon_in_galans_mock.assert_called_once_with(json_req)
        self.faucet.request_neon_in_galans_mock.reset_mock()


    @patch.object(PriceProvider, 'get_price')
    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_failed_process_trx_with_one_airdrop_price_provider_error(self,
                                                                      mock_sql_dict_contains,
                                                                      mock_sql_dict_setitem,
                                                                      mock_get_price):
        """
        Should not airdrop to new address due to price provider error
        """
        mock_get_price.side_effect = [None]
        mock_sql_dict_contains.side_effect = [False] # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=200, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_sql_dict_setitem.assert_not_called()
        mock_get_price.assert_called_once_with('SOL/USD')
        self.faucet.request_neon_in_galans_mock.assert_not_called()
        self.faucet.request_neon_in_galans_mock.reset_mock()


    @patch.object(Airdropper, '_is_allowed_wrapper_contract')
    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_failed_airdrop_contract_not_in_whitelist(self,
                                                      mock_sql_dict_contains,
                                                      mock_sql_dict_setitem,
                                                      mock_is_allowed_contract):
        """
        Should not airdrop for contract that is not in whitelist
        """
        mock_is_allowed_contract.side_effect = [False]
        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_is_allowed_contract.assert_called_once()
        mock_sql_dict_contains.assert_not_called()
        mock_sql_dict_setitem.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()
        self.faucet.request_neon_in_galans_mock.reset_mock()


    @patch.object(PriceProvider, 'get_price')
    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_faucet_failure(self,
                            mock_sql_dict_contains,
                            mock_sql_dict_setitem,
                            mock_get_price):
        """
        Should not add address to processed list due to faucet error
        """
        sol_price = 341
        airdrop_amount = int(pow(10, self.neon_decimals) * (AIRDROP_AMOUNT_SOL * sol_price) / NEON_PRICE_USD)
        mock_get_price.side_effect = [sol_price]
        mock_sql_dict_contains.side_effect = [False]  # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=400, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_get_price.assert_called_once_with('SOL/USD')
        mock_sql_dict_setitem.assert_not_called()
        json_req = {'wallet': token_airdrop_address1, 'amount': airdrop_amount}
        self.faucet.request_neon_in_galans_mock.assert_called_once_with(json_req)
        self.faucet.request_neon_in_galans_mock.reset_mock()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_process_trx_with_one_airdrop_for_already_processed_address(self,
                                                                        mock_sql_dict_contains,
                                                                        mock_sql_dict_setitem):
        """
        Should not airdrop to repeated address
        """
        mock_sql_dict_contains.side_effect = [True]  # eth address processed later

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx1)

        mock_sql_dict_contains.assert_called_once_with(token_airdrop_address1)
        mock_sql_dict_setitem.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()
        self.faucet.request_neon_in_galans_mock.reset_mock()


    @patch.object(PriceProvider, 'get_price')
    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_complex_transation(self,
                                mock_sql_dict_contains,
                                mock_sql_dict_setitem,
                                mock_get_price):
        """
        Should airdrop to several targets in one transaction
        """
        sol_price1 = 341
        sol_price2 = 225
        airdrop_amount1 = int(pow(10, self.neon_decimals) * (AIRDROP_AMOUNT_SOL * sol_price1) / NEON_PRICE_USD)
        airdrop_amount2 = int(pow(10, self.neon_decimals) * (AIRDROP_AMOUNT_SOL * sol_price2) / NEON_PRICE_USD)
        mock_get_price.side_effect = [sol_price1, sol_price2]
        mock_sql_dict_contains.side_effect = [False, False] # both targets are new
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=200, mimetype='application/json'),
                                                               Response("{}", status=200, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx2)

        mock_sql_dict_contains.assert_has_calls([call(token_airdrop_address3),
                                                 call(token_airdrop_address2)])
        mock_get_price.assert_has_calls([call('SOL/USD')]* 2)
        mock_sql_dict_setitem.assert_has_calls([call(token_airdrop_address3, ANY),
                                                call(token_airdrop_address2, ANY)])
        json_req1 = {'wallet': token_airdrop_address2, 'amount': airdrop_amount2}
        json_req2 = {'wallet': token_airdrop_address3, 'amount': airdrop_amount1}
        self.faucet.request_neon_in_galans_mock.assert_has_calls([call(json_req2), call(json_req1)])
        self.faucet.request_neon_in_galans_mock.reset_mock()


    @patch.object(SQLDict, '__setitem__')
    @patch.object(SQLDict, '__contains__')
    def test_no_airdrop_instructions(self,
                                     mock_sql_dict_contains,
                                     mock_sql_dict_setitem):
        """
        Should not airdrop when instructions are inconsistent
        """
        self.airdropper.process_trx_airdropper_mode(create_sol_acc_and_airdrop_trx)

        mock_sql_dict_contains.assert_not_called()
        mock_sql_dict_setitem.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()
        self.faucet.request_neon_in_galans_mock.reset_mock()

