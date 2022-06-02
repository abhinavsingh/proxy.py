import unittest

from solana.publickey import PublicKey
from ..indexer.pythnetwork import PythNetworkClient
from ..common_neon.gas_price_calculator import GasPriceCalculator
from solana.rpc.api import Client as SolanaClient
from unittest.mock import patch, call, Mock
from decimal import Decimal
from ..common_neon.environment_data import OPERATOR_FEE, NEON_PRICE_USD, SOL_PRICE_UPDATE_INTERVAL, \
                                           GET_SOL_PRICE_MAX_RETRIES

MINIMAL_GAS_PRICE = None


class TestGasPriceCalculator(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mapping_account = PublicKey('BmA9Z6FjioHJPpjT39QazZyhDRUdZy2ezwx4GiDdE2u2')  # only for devnet
        cls.solana_url = "https://api.devnet.solana.com" # devnet
        cls.solana_client = SolanaClient(cls.solana_url)
        cls.testee = GasPriceCalculator(cls.solana_client, cls.mapping_account)
        cls.testee.env_min_gas_price = Mock()
        cls.testee.env_min_gas_price.return_value = None


    def setUp(self) -> None:
        # reset time on test begins
        self.testee.recent_sol_price_update_time = None


    @patch.object(GasPriceCalculator, 'get_current_time')
    @patch.object(PythNetworkClient, 'get_price')
    def test_success_update_price(self, mock_get_price, mock_get_current_time):
        """
        Should succesfully calculate gas price on first attempt
        """
        sol_price = Decimal('156.3')

        mock_get_current_time.side_effect = [1234]
        mock_get_price.side_effect = [{'status': 1, 'price': sol_price}]

        self.testee.reset()
        gas_price = self.testee.get_min_gas_price()
        expected_price = (sol_price / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
        self.assertEqual(gas_price, expected_price)

        mock_get_current_time.assert_called_once()
        mock_get_price.assert_called_once_with('Crypto.SOL/USD')


    @patch.object(GasPriceCalculator, 'get_current_time')
    @patch.object(PythNetworkClient, 'get_price')
    def test_success_update_price_after_retry_due_to_wrong_price_status(self, mock_get_price, mock_get_current_time):
        """
        Should retry get_price after wrong price status
        """
        sol_price = Decimal('156.3')

        mock_get_current_time.side_effect = [1234]
        mock_get_price.side_effect = [
            {'status': 0, 'price': sol_price}, # <--- Wrong price status
            {'status': 1, 'price': sol_price}
        ]

        self.testee.reset()
        gas_price = self.testee.get_min_gas_price()
        expected_price = (sol_price / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
        self.assertEqual(gas_price, expected_price)

        mock_get_current_time.assert_called_once()
        mock_get_price.assert_has_calls([call('Crypto.SOL/USD')] * 2)


    @patch.object(GasPriceCalculator, 'get_current_time')
    @patch.object(PythNetworkClient, 'get_price')
    def test_success_update_price_after_retry_due_to_get_price_exception(self, mock_get_price, mock_get_current_time):
        """
        Should retry get_price after exception
        """
        self.assertGreater(GET_SOL_PRICE_MAX_RETRIES, 1) # Condition required to start test
        sol_price = Decimal('156.3')

        mock_get_current_time.side_effect = [1234]
        mock_get_price.side_effect = [
            Exception("Test exception happened"),
            {'status': 1, 'price': sol_price}
        ]

        self.testee.reset()
        gas_price = self.testee.get_min_gas_price()
        expected_price = (sol_price / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
        self.assertEqual(gas_price, expected_price)

        mock_get_current_time.assert_called_once()
        mock_get_price.assert_has_calls([call('Crypto.SOL/USD')] * 2)


    @patch.object(GasPriceCalculator, 'get_current_time')
    @patch.object(PythNetworkClient, 'get_price')
    def test_failed_update_retries_exhausted(self, mock_get_price, mock_get_current_time):
        """
        Should throw exception after all retries exhausted
        """
        self.assertGreater(GET_SOL_PRICE_MAX_RETRIES, 1) # Condition required to start test
        sol_price = Decimal('156.3')

        mock_get_current_time.side_effect = [1234]
        mock_get_price.side_effect = [ Exception("Test exception happened") ] * GET_SOL_PRICE_MAX_RETRIES

        with self.assertRaises(Exception):
            self.testee.get_min_gas_price()

        mock_get_current_time.assert_called_once()
        mock_get_price.assert_has_calls([call('Crypto.SOL/USD')] * GET_SOL_PRICE_MAX_RETRIES)


    @patch.object(GasPriceCalculator, 'get_current_time')
    @patch.object(PythNetworkClient, 'get_price')
    def test_success_get_price_time_intervals(self, mock_get_price, mock_get_current_time):
        """
        Should successfully calculate gas price:
            - with no get_price call on second attempt (time interval too small)
            - with get_price call on first and third attempt
        """

        time1 = 1234
        time2 = time1 + SOL_PRICE_UPDATE_INTERVAL - 1 # small interval
        time3 = time2 + SOL_PRICE_UPDATE_INTERVAL + 1 # big interval
        mock_get_current_time.side_effect = [time1, time2, time3]

        sol_price1 = Decimal('156.3')
        sol_price2 = Decimal('156.3')
        mock_get_price.side_effect = [
            {'status': 1, 'price': sol_price1},
            {'status': 1, 'price': sol_price2}]

        gas_price1 = self.testee.get_min_gas_price()
        expected_price1 = (sol_price1 / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
        self.assertEqual(gas_price1, expected_price1)

        gas_price2 = self.testee.get_min_gas_price()
        self.assertEqual(gas_price2, expected_price1)

        gas_price3 = self.testee.get_min_gas_price()
        expected_price2 = (sol_price2 / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
        self.assertEqual(gas_price3, expected_price2)

        mock_get_current_time.assert_has_calls([call()] * 3)
        mock_get_price.assert_has_calls([call('Crypto.SOL/USD')] * 2)
