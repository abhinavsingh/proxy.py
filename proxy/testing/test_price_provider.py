from proxy.indexer.price_provider import PriceProvider, field_info, PRICE_STATUS_TRADING,\
    PRICE_STATUS_UNKNOWN, \
    testnet_price_accounts, \
    devnet_price_accounts, \
    mainnet_price_accounts, \
    mainnet_solana, \
    testnet_solana, \
    devnet_solana
from unittest import TestCase
from unittest.mock import patch, MagicMock, call
from solana.rpc.api import Client
from solana.publickey import PublicKey
from struct import pack
from random import uniform
import base58, base64


def _create_price_account_info(price: float, status: int, enc: str):
    # Follow link https://github.com/pyth-network/pyth-client-rs/blob/main/src/lib.rs
    # for details on structure of pyth.network price accounts.
    # Current implementation of PriceProvider uses only few fields of account
    # so no need to generate all data in tests

    exponent = -8  # use as default
    # Fill gap between account data begining and expo field with zeros
    data = b'\x00' * field_info['expo']['pos']
    data += pack(field_info['expo']['format'], exponent)

    raw_price = int(price / pow(10, exponent))
    # fill gap between expo and agg.price fields with zeros
    data += b'\x00' * (field_info['agg.price']['pos'] - len(data))
    data += pack(field_info['agg.price']['format'], raw_price)

    # fill gap between agg.price and agg.status fields with zeros
    data += b'\x00' * (field_info['agg.status']['pos'] - len(data))
    data += pack(field_info['agg.status']['format'], status)
    # rest of data array is not used by PriceProvier so no need to fill it

    if enc == 'base58':
        data = base58.b58encode(data)
    elif enc == 'base64':
        data = base64.b64encode(data)
    else:
        raise Exception(f"Unsupported encoding: {enc}")

    return {'result': {'value': {'data': [data, enc]}}}


class TestPriceProvider(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("Testing PriceProvider")
        cls.default_upd_int = 10


    def setUp(self) -> None:
        print(f"\n\n{self._testMethodName}\n{self._testMethodDoc}")
        self.testnet_price_provider = PriceProvider(testnet_solana,
                                                    self.default_upd_int,
                                                    testnet_price_accounts)


    @patch.object(Client, 'get_account_info')
    @patch.object(PriceProvider, '_get_current_time')
    def test_success_read_price_two_times_with_small_interval(self, mock_get_current_time, mock_get_account_info):
        """
        Testing two sequential calls with small interval. Should read account once
        """
        first_call_time =  uniform(0, 100000) # some random time
        # not enough time left to cause second account reload
        second_call_time = first_call_time + self.default_upd_int - 1

        mock_get_current_time.side_effect = [ first_call_time, second_call_time]

        current_price = 315.0
        mock_get_account_info.side_effect = [_create_price_account_info(current_price,
                                                                        PRICE_STATUS_TRADING,
                                                                        'base58')]

        pair_name = 'SOL/USD'
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), current_price)
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), current_price)

        mock_get_current_time.assert_has_calls([call(), call()])
        mock_get_account_info.assert_called_once_with(PublicKey(testnet_price_accounts[pair_name]))


    @patch.object(Client, 'get_account_info')
    @patch.object(PriceProvider, '_get_current_time')
    def test_success_read_price_two_times_with_long_interval_diff_encodings(self, mock_get_current_time, mock_get_account_info):
        """
        Testing two sequential calls with long interval. Should read account twice
        """
        first_call_time =  uniform(0, 100000) # some random time
        # Time interval between 1st and 2nd calls are larger that reload interval
        second_call_time = first_call_time + self.default_upd_int + 2

        mock_get_current_time.side_effect = [ first_call_time, second_call_time]

        current_price = 315.0
        mock_get_account_info.side_effect = [_create_price_account_info(current_price,
                                                                        PRICE_STATUS_TRADING,
                                                                        'base58'),
                                             _create_price_account_info(current_price,
                                                                        PRICE_STATUS_TRADING,
                                                                        'base64')]

        pair_name = 'SOL/USD'
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), current_price)
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), current_price)

        price_acc_key = PublicKey(testnet_price_accounts[pair_name])
        mock_get_current_time.assert_has_calls([call(), call()])
        mock_get_account_info.assert_has_calls([call(price_acc_key), call(price_acc_key)])

    @patch.object(Client, 'get_account_info')
    @patch.object(PriceProvider, '_get_current_time')
    def test_faile_get_price_price_status_not_trading(self, mock_get_current_time, mock_get_account_info):
        """
        get_price call should return None because last price account data is not trading
        """
        first_call_time = uniform(0, 100000) # some random time

        mock_get_current_time.side_effect = [first_call_time]

        current_price = 315.0
        mock_get_account_info.side_effect = [_create_price_account_info(current_price,
                                                                        PRICE_STATUS_UNKNOWN,
                                                                        'base58')]

        pair_name = 'SOL/USD'
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), None)

        price_acc_key = PublicKey(testnet_price_accounts[pair_name])
        mock_get_current_time.assert_has_calls([call()])
        mock_get_account_info.assert_has_calls([call(price_acc_key)])


    @patch.object(Client, 'get_account_info')
    @patch.object(PriceProvider, '_get_current_time')
    def test_failed_read_account_not_found(self, mock_get_current_time, mock_get_account_info):
        """
        Account reading will fail due to unknown pair provided
        """
        first_call_time =  uniform(0, 100000) # some random time
        mock_get_current_time.side_effect = [ first_call_time ]

        pair_name = 'RUB/USD' # Unknown pair
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), None)

        mock_get_current_time.assert_has_calls([call()])
        mock_get_account_info.assert_not_called()


    @patch.object(Client, 'get_account_info')
    @patch.object(PriceProvider, '_get_current_time')
    def test_failed_second_acc_read_will_return_previous_result(self, mock_get_current_time, mock_get_account_info):
        """
        Testing two sequential calls with long interval. Second call will fail. Provider should return previous price
        """
        first_call_time =  uniform(0, 100000) # some random time
        # Time interval between 1st and 2nd calls are larger that reload interval
        second_call_time = first_call_time + self.default_upd_int + 2

        mock_get_current_time.side_effect = [ first_call_time, second_call_time]

        current_price = 315.0
        mock_get_account_info.side_effect = [_create_price_account_info(current_price,
                                                                        PRICE_STATUS_TRADING,
                                                                        'base58'),
                                             {'result':{}}] # << Wrong message format

        pair_name = 'SOL/USD'
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), current_price)
        self.assertEqual(self.testnet_price_provider.get_price(pair_name), current_price)

        price_acc_key = PublicKey(testnet_price_accounts[pair_name])
        mock_get_current_time.assert_has_calls([call(), call()])
        mock_get_account_info.assert_has_calls([call(price_acc_key), call(price_acc_key)])


    def test_compare_mainnet_testnet_data(self):
        """
        Should return correct prices on all Solana nets
        """
        pair_name = 'SOL/USD'

        devnet_price_provider = PriceProvider(devnet_solana,
                                              self.default_upd_int,
                                              devnet_price_accounts)
        mainnet_price_provider = PriceProvider(mainnet_solana,
                                               self.default_upd_int,
                                               mainnet_price_accounts)

        devnet_price = devnet_price_provider.get_price(pair_name)
        testnet_price = self.testnet_price_provider.get_price(pair_name)
        mainnet_price =  mainnet_price_provider.get_price(pair_name)

        print(f"Solana devnet: SOL/USD = {devnet_price}")
        print(f"Solana testnet: SOL/USD = {testnet_price}")
        print(f"Solana mainnet: SOL/USD = {mainnet_price}")

        self.assertTrue(devnet_price is not None)
        self.assertTrue(testnet_price is not None)
        self.assertTrue(mainnet_price is not None)
