from solana.rpc.api import Client as SolanaClient
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID
from decimal import Decimal
import base64
import base58
import struct
from logged_groups import logged_group


def read_str(pos, data):
    length = data[pos]
    start = pos + 1
    stop = pos + 1 + length
    return data[start:stop], stop


def read_keyvalue(pos, data):
    key, pos = read_str(pos, data)
    value, pos = read_str(pos, data)
    return key, value, pos


def read_dict(data):
    pos = 0
    result = {}
    while pos < len(data):
        key, value, pos = read_keyvalue(pos, data)
        if len(key) == 0 or len(value) == 0:
            break
        result[key.decode('utf-8')] = value.decode('utf-8')
    return result


def unpack(layout_descriptor, raw_data, field_name, index = 0):
    field = layout_descriptor.get(field_name, None)
    if field is None:
        raise Exception(f'Unknown field name: {field_name}')

    length = field['len']
    start_idx = field['pos'] + index * length
    stop_idx = start_idx + length
    if field['format'] == 'acc': # special case for Solana account address
        return PublicKey(raw_data[start_idx:stop_idx])
    elif field['format'] == 'dict': # special case for attribute mapping
        return read_dict(raw_data[start_idx:stop_idx])
    return struct.unpack(field['format'], raw_data[start_idx:stop_idx])[0]


@logged_group("neon.Airdropper")
class PythNetworkClient:
    PYTH_MAGIC = 0xa1b2c3d4
    PROD_ACCT_SIZE = 512
    PROD_HDR_SIZE = 48
    PROD_ATTR_SIZE = PROD_ACCT_SIZE - PROD_HDR_SIZE
    SUPPORTED_VERSIONS = [2]

    base_account_layout = {
        'magic': {'pos': 0, 'len': 4, 'format': '<I'},
        'ver': {'pos': 4, 'len': 4, 'format': '<I'}
    }

    mapping_account_layout = {
        'num_products': { 'pos': 16, 'len': 4, 'format': '<I' },
        'next': {'pos': 24, 'len': 32, 'format': 'acc' },
        'product': {'pos': 56, 'len': 32, 'format': 'acc' }
    }


    product_account_layout = {
        'magic': { 'pos': 0, 'len': 4, 'format': '<I' },
        'price_acc': { 'pos': 16, 'len': 32, 'format': 'acc' },
        'attrs': { 'pos': 48, 'len': PROD_ATTR_SIZE, 'format': 'dict' }
    }

    price_account_layout = {
        'expo': { 'pos': 20, 'len': 4, 'format': '<i' },
        'valid_slot': { 'pos': 40, 'len': 8, 'format': '<Q' },
        'agg.price': { 'pos': 208, 'len': 8, 'format': '<q' },
        'agg.conf': { 'pos': 216, 'len': 8, 'format': '<Q' },
        'agg.status': { 'pos': 224, 'len': 4, 'format': '<I' },
    }

    def __init__(self, client: SolanaClient):
        self.client = client
        self.price_accounts = {}

    def read_pyth_acct_data(self, acc_addr: PublicKey):
        response = self.client.get_account_info(acc_addr)
        result = response.get('result', None)
        if result is None:
            raise RuntimeError(f'Failed to retrieve data of pyth account {acc_addr}')

        value = result.get('value', None)
        if value is None:
            raise RuntimeError(f'Failed to retrieve data of pyth account {acc_addr}')

        data = value.get('data', None)
        if not isinstance(data, list) or len(data) != 2:
            raise RuntimeError(f"Wrong account's data format {acc_addr}")

        encoding = data[1]
        if encoding == 'base58':
            data = base58.b58decode(data[0])
        elif encoding == 'base64':
            data = base64.b64decode(data[0])
        else:
            raise RuntimeError(f'Unknown encoding {encoding} in account {acc_addr}')

        magic = unpack(self.base_account_layout, data, 'magic')
        if magic != self.PYTH_MAGIC:
            raise RuntimeError(f'Wrong magic {magic} in account {acc_addr}')

        version = unpack(self.base_account_layout, data, 'ver')
        if not version in self.SUPPORTED_VERSIONS:
            raise RuntimeError(f'Pyth.Network version not supported: {version}')

        return data

    def parse_mapping_account(self, acc_addr: PublicKey):
        products = []
        while acc_addr != SYS_PROGRAM_ID:
            data = self.read_pyth_acct_data(acc_addr)
            num_products = unpack(self.mapping_account_layout, data, 'num_products')
            acc_addr = unpack(self.mapping_account_layout, data, 'next')
            for i in range(num_products):
                products.append(unpack(self.mapping_account_layout, data, 'product', i))
        return products

    def parse_prod_account(self, acc_addr: PublicKey):
        data = self.read_pyth_acct_data(acc_addr)
        return {
            'price_acc': unpack(self.product_account_layout, data, 'price_acc'),
            'attrs': unpack(self.product_account_layout, data, 'attrs')
        }

    def parse_price_account(self, acc_addr: PublicKey):
        data = self.read_pyth_acct_data(acc_addr)
        price = Decimal(unpack(self.price_account_layout, data, 'agg.price'))
        conf = Decimal(unpack(self.price_account_layout, data, 'agg.conf'))
        multiply = pow(Decimal(10), unpack(self.price_account_layout, data, 'expo'))
        return {
            'valid_slot':   unpack(self.price_account_layout, data, 'valid_slot'),
            'price':        price * multiply,
            'conf':         conf * multiply,
            'status':       unpack(self.price_account_layout, data, 'agg.status')
        }

    def update_mapping(self, mapping_acc: PublicKey):
        """
        Reads pyth.network mapping account and prepares mapping
        symbol -> price_acc_addr
        """
        product_list = self.parse_mapping_account(mapping_acc)
        idx = 0
        for prod_acc in product_list:
            try:
                idx += 1
                product = self.parse_prod_account(prod_acc)
                symbol = product['attrs']['symbol']
                self.info(f'Product account {prod_acc}: {symbol}')
                self.price_accounts[symbol] = product['price_acc']
            except Exception as err:
                self.error(f'Failed to read product account {prod_acc}: {err}')
                continue

    def get_price(self, symbol):
        """
        Return price data given product symbol.
        Throws exception if symbol is absent in preloaded product map
        or error occured when loading/parsing price account
        """
        return self.parse_price_account(self.price_accounts[symbol])
