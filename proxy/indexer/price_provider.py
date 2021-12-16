from solana.rpc.api import Client
from solana.publickey import PublicKey
import base64
import base58
import struct
from datetime import datetime
from logging import Logger

logger = Logger(__name__)

field_info = {
  'expo': { 'pos': 20, 'len': 4, 'format': '<i' },
  'agg.price': { 'pos': 208, 'len': 8, 'format': '<q' },
  'agg.conf': { 'pos': 216, 'len': 8, 'format': '<Q' },
  'agg.status': { 'pos': 224, 'len': 4, 'format': '<I' },
}


def _unpack_field(raw_data: bytes, field_name: str):
    field = field_info.get(field_name, None)
    if field is None:
        raise Exception(f'Unknown field name: {field_name}')

    start_idx = field['pos']
    stop_idx = field['pos'] + field['len']
    return struct.unpack(field['format'], raw_data[start_idx:stop_idx])[0]


mainnet_solana = "https://api.mainnet-beta.solana.com"
devnet_solana = "https://api.devnet.solana.com"
testnet_solana = "https://api.testnet.solana.com"


# See available price accounts at https://pyth.network/developers/accounts/
mainnet_price_accounts = { 'SOL/USD': 'H6ARHf6YXhGYeQfUzQNGk6rDNnLBQKrenN712K4AQJEG' }
devnet_price_accounts = { 'SOL/USD': "J83w4HKfqxwcq3BEMMkPFSppX3gqekLyLJBexebFVkix" }
testnet_price_accounts = { 'SOL/USD': "7VJsBtJzgTftYzEeooSDYyjKXvYRWJHdwvbwfBvTg9K" }


PRICE_STATUS_UNKNOWN = 0
PRICE_STATUS_TRADING = 1


class PriceProvider:
    def __init__(self, solana_url: str, default_upd_int: int, price_accounts=None):
        self.client = Client(solana_url)
        self.default_upd_int = default_upd_int
        self.prices = {}
        if price_accounts is not None:
            self.price_accounts = price_accounts
        else:
            self.price_accounts = {}


    def _get_current_time(self):
        return datetime.now().timestamp()


    def _read_price(self, pairname):
        acc_id = self.price_accounts.get(pairname, None)
        if acc_id is None:
            logger.warning(f'No account found for pair {pairname}')
            return None

        response = self.client.get_account_info(PublicKey(acc_id))
        result = response.get('result', None)
        if result is None:
            logger.warning(f'Failed to read account data for account {acc_id}')
            return None

        value = result.get('value', None)
        if value is None:
            logger.warning(f'Failed to read account data for account {acc_id}')
            return None

        data = value.get('data', None)
        if not isinstance(data, list) or len(data) != 2:
            logger.warning(f'Failed to read account data for account {acc_id}')
            return None

        encoding = data[1]
        if encoding == 'base58':
            data = base58.b58decode(data[0])
        elif encoding == 'base64':
            data = base64.b64decode(data[0])
        else:
            logger.warning(f'Unknown encoding {encoding}')
            return None

        status = _unpack_field(data, 'agg.status')
        if status != PRICE_STATUS_TRADING: # not Trading
            logger.warning(f'Price status is {status}')
            return None

        expo = _unpack_field(data, 'expo')
        price = _unpack_field(data, 'agg.price')
        return price * pow(10, expo)


    def get_price(self, pairname):
        price_data = self.prices.get(pairname, None)
        current_time = self._get_current_time()

        if price_data == None or current_time - price_data['last_update'] >= self.default_upd_int:
            current_price = self._read_price(pairname)
            if current_price is not None:
                self.prices[pairname] = { 'price': current_price, 'last_update': current_time }
                return current_price

            if price_data is not None:
                return price_data['price']
            else:
                return None
        # price_data is not None and current_time - price_data['last_update'] < self.default_upd_int
        return price_data['price']


