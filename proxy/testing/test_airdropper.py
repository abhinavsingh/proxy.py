import os
import unittest

from solana.publickey import PublicKey
from proxy.testing.mock_server import MockServer
from proxy.indexer.airdropper import Airdropper, AIRDROP_AMOUNT_SOL, NEON_PRICE_USD
from proxy.indexer.sql_dict import SQLDict
from proxy.common_neon.solana_interactor import SolanaInteractor
import time
from flask import request, Response
from unittest.mock import Mock, MagicMock, patch, ANY
from decimal import Decimal
import itertools
from proxy.testing.transactions import pre_token_airdrop_trx, wrapper_whitelist, evm_loader_addr, token_airdrop_address


SOLANA_URL = os.environ.get("SOLANA_URL", "http://solana:8899")


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

def create_price_info(valid_slot: int, price: Decimal, conf: Decimal):
    return {
        'valid_slot':   valid_slot,
        'price':        price,
        'conf':         conf
    }


class Test_Airdropper(unittest.TestCase):
    def create_airdropper(self, start_slot):
        os.environ['START_SLOT'] = str(start_slot)
        return Airdropper(solana_url          =SOLANA_URL,
                          pyth_mapping_account=self.pyth_mapping_account,
                          faucet_url          =f'http://{self.address}:{self.faucet_port}',
                          wrapper_whitelist   =self.wrapper_whitelist,
                          neon_decimals       =self.neon_decimals)

    @classmethod
    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def setUpClass(cls, mock_get_slot, mock_dict_get) -> None:
        print("testing indexer in airdropper mode")
        cls.address = 'localhost'
        cls.faucet_port = 3333
        cls.evm_loader_id = evm_loader_addr
        cls.pyth_mapping_account = PublicKey(b'TestMappingAccount')
        cls.wrapper_whitelist = wrapper_whitelist
        cls.neon_decimals = 9
        cls.airdropper = cls.create_airdropper(cls, 0)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

        cls.airdropper.always_reload_price = True

        cls.mock_pyth_client = Mock()
        cls.mock_pyth_client.get_price = MagicMock()
        cls.mock_pyth_client.update_mapping = MagicMock()
        cls.airdropper.pyth_client = cls.mock_pyth_client

        cls.mock_airdrop_ready = Mock()
        cls.mock_airdrop_ready.register_airdrop = MagicMock()
        cls.mock_airdrop_ready.is_airdrop_ready = MagicMock()
        cls.airdropper.airdrop_ready = cls.mock_airdrop_ready

        cls.mock_failed_attempts = Mock()
        cls.mock_failed_attempts.airdrop_failed = MagicMock()
        cls.airdropper.failed_attempts = cls.mock_failed_attempts

    def setUp(self) -> None:
        print(f"\n\n{self._testMethodName}\n{self._testMethodDoc}")
        self.faucet = MockFaucet(self.faucet_port)
        self.faucet.start()
        self.airdropper.last_update_pyth_mapping = None
        time.sleep(0.2)

    def tearDown(self) -> None:
        self.faucet.shutdown_server()
        self.faucet.join()
        self.airdropper.airdrop_scheduled.clear()
        self.mock_airdrop_ready.is_airdrop_ready.reset_mock()
        self.mock_airdrop_ready.register_airdrop.reset_mock()
        self.mock_pyth_client.get_price.reset_mock()
        self.mock_pyth_client.update_mapping.reset_mock()
        self.mock_failed_attempts.airdrop_failed.reset_mock()

    def test_failed_process_trx_with_one_airdrop_price_provider_error(self):
        """
        Should not airdrop to new address due to price provider error
        """

        self.mock_pyth_client.get_price.side_effect = Exception('TestException')
        self.mock_airdrop_ready.is_airdrop_ready.side_effect = [False] # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=200, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx)
        self.airdropper.process_scheduled_trxs()

        self.mock_failed_attempts.airdrop_failed.assert_called_once_with('ALL', ANY)
        self.mock_pyth_client.update_mapping.assert_called_once()
        self.mock_airdrop_ready.is_airdrop_ready.assert_called_once_with(token_airdrop_address)
        self.mock_airdrop_ready.register_airdrop.assert_not_called()
        self.mock_pyth_client.get_price.assert_called_once_with('Crypto.SOL/USD')
        self.faucet.request_neon_in_galans_mock.assert_not_called()

    @patch.object(Airdropper, 'is_allowed_wrapper_contract')
    def test_failed_airdrop_contract_not_in_whitelist(self, mock_is_allowed_contract):
        """
        Should not airdrop for contract that is not in whitelist
        """
        self.airdropper.current_slot = 1
        self.mock_pyth_client.get_price.side_effect = [{
            'valid_slot': self.airdropper.current_slot,
            'price': Decimal('235.0'),
            'conf': Decimal('1.3'),
            'status': 1
        }]

        mock_is_allowed_contract.side_effect = [False]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx)
        self.airdropper.process_scheduled_trxs()

        self.mock_failed_attempts.airdrop_failed.assert_not_called()
        self.mock_pyth_client.update_mapping.assert_called_once()
        mock_is_allowed_contract.assert_called_once()
        self.mock_pyth_client.get_price.assert_called_once_with('Crypto.SOL/USD')
        self.mock_airdrop_ready.is_airdrop_ready.assert_not_called()
        self.mock_airdrop_ready.register_airdrop.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()

    def test_faucet_failure(self):
        """
        Should not add address to processed list due to faucet error
        """
        sol_price = Decimal('341.5')
        airdrop_amount = int(pow(Decimal(10), self.neon_decimals) * (AIRDROP_AMOUNT_SOL * sol_price) / NEON_PRICE_USD)
        self.airdropper.current_slot = 2
        self.mock_pyth_client.get_price.side_effect = [{
            'valid_slot': self.airdropper.current_slot,
            'price': sol_price,
            'conf': Decimal('1.3'),
            'status': 1
        }]

        self.mock_airdrop_ready.is_airdrop_ready.side_effect = [False]  # new eth address
        self.faucet.request_neon_in_galans_mock.side_effect = [Response("{}", status=400, mimetype='application/json')]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx)
        self.airdropper.process_scheduled_trxs()

        self.mock_failed_attempts.airdrop_failed.assert_called_once_with(str(token_airdrop_address), ANY)
        self.mock_pyth_client.update_mapping.assert_called_once()
        self.mock_airdrop_ready.is_airdrop_ready.assert_called_once_with(token_airdrop_address)
        self.mock_pyth_client.get_price.assert_called_once_with('Crypto.SOL/USD')
        self.mock_airdrop_ready.register_airdrop.assert_not_called()
        json_req = {'wallet': token_airdrop_address, 'amount': airdrop_amount}
        self.faucet.request_neon_in_galans_mock.assert_called_once_with(json_req)

    def test_process_trx_with_one_airdrop_for_already_processed_address(self):
        """
        Should not airdrop to repeated address
        """
        self.airdropper.current_slot = 1
        self.mock_pyth_client.get_price.side_effect = [{
            'valid_slot': self.airdropper.current_slot,
            'price': Decimal('235.0'),
            'conf': Decimal('1.3'),
            'status': 1
        }]

        self.mock_airdrop_ready.is_airdrop_ready.side_effect = [True]  # eth address processed earlier

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx)
        self.airdropper.process_scheduled_trxs()

        self.mock_pyth_client.update_mapping.assert_called_once()
        self.mock_pyth_client.get_price.assert_called_once_with('Crypto.SOL/USD')
        self.mock_failed_attempts.airdrop_failed.assert_not_called()
        self.mock_airdrop_ready.is_airdrop_ready.assert_called_once_with(token_airdrop_address)
        self.mock_airdrop_ready.register_airdrop.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()

    def test_failed_airdrop_confidence_interval_too_large(self):
        """
        Should not airdrop because confidence interval too large
        """
        self.airdropper.current_slot = 3
        self.mock_pyth_client.get_price.side_effect = [{
            'valid_slot': self.airdropper.current_slot,
            'price': Decimal('235.0'),
            'conf': Decimal('54.0'),
            'status': 1
        }]

        self.airdropper.process_trx_airdropper_mode(pre_token_airdrop_trx)
        self.airdropper.process_scheduled_trxs()

        self.mock_pyth_client.update_mapping.assert_called_once()
        self.mock_pyth_client.get_price.assert_called_once_with('Crypto.SOL/USD')
        self.mock_airdrop_ready.is_airdrop_ready.assert_called_once_with(token_airdrop_address)
        self.mock_airdrop_ready.register_airdrop.assert_not_called()
        self.faucet.request_neon_in_galans_mock.assert_not_called()

    def test_update_mapping_error(self):
        self.mock_pyth_client.update_mapping.side_effect = [Exception('TestException')]
        try:
            self.airdropper.process_scheduled_trxs()
            self.mock_pyth_client.update_mapping.assert_called_once()
            self.mock_pyth_client.get_price.assert_not_called()
        except Exception as err:
            self.fail(f'Excpected not throws exception but it does: {err}')

    def test_get_price_error(self):
        self.mock_pyth_client.get_price.side_effect = [Exception('TestException')]
        try:
            self.airdropper.process_scheduled_trxs()
            self.mock_pyth_client.update_mapping.assert_called_once()
            self.mock_pyth_client.get_price.assert_called_once_with('Crypto.SOL/USD')
        except Exception as err:
            self.fail(f'Excpected not throws exception but it does: {err}')

    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def test_init_airdropper_slot_continue(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [{'result': start_slot + 1}]
        new_airdropper = self.create_airdropper('CONTINUE')
        self.assertEqual(new_airdropper.latest_processed_slot, start_slot - 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def test_init_airdropper_slot_continue_recent_slot_not_found(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [None]
        mock_get_slot.side_effect = [{'result': start_slot + 1}]
        new_airdropper = self.create_airdropper('CONTINUE')
        self.assertEqual(new_airdropper.latest_processed_slot, start_slot + 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def test_init_airdropper_start_slot_parse_error(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [{'result': start_slot + 1}]
        new_airdropper = self.create_airdropper('Wrong value')
        self.assertEqual(new_airdropper.latest_processed_slot, start_slot - 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def test_init_airdropper_slot_latest(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [{'result': start_slot + 1}]
        new_airdropper = self.create_airdropper('LATEST')
        self.assertEqual(new_airdropper.latest_processed_slot, start_slot + 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def test_init_airdropper_slot_number(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [{'result': start_slot + 1}]
        new_airdropper = self.create_airdropper(str(start_slot))
        self.assertEqual(new_airdropper.latest_processed_slot, start_slot)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()

    @patch.object(SQLDict, 'get')
    @patch.object(SolanaInteractor, 'get_slot')
    def test_init_airdropper_big_slot_number(self, mock_get_slot, mock_dict_get):
        start_slot = 1234
        mock_dict_get.side_effect = [start_slot - 1]
        mock_get_slot.side_effect = [{'result': start_slot + 1}]
        new_airdropper = self.create_airdropper(str(start_slot + 100))
        self.assertEqual(new_airdropper.latest_processed_slot, start_slot + 1)
        mock_get_slot.assert_called_once_with('finalized')
        mock_dict_get.assert_called()
