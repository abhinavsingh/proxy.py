from solana.rpc.api import Client as SolanaClient
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID
from decimal import Decimal
import base64
import base58
import struct
from logged_groups import logged_group
from typing import List, Union


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


@logged_group("neon.airdropper")
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

    def parse_pyth_account_data(self, acct_addr, acct_info_value):
        # it is possible when calling to getMultipleAccounts (if some accounts are absent in blockchain)
        if acct_info_value is None:
            return None

        data = acct_info_value.get('data', None)
        if not isinstance(data, list) or len(data) != 2:
            raise RuntimeError(f"Wrong account's data format")

        encoding = data[1]
        if encoding == 'base58':
            data = base58.b58decode(data[0])
        elif encoding == 'base64':
            data = base64.b64decode(data[0])
        else:
            raise RuntimeError(f'Unknown encoding {encoding} in account {acct_addr}')

        magic = unpack(self.base_account_layout, data, 'magic')
        if magic != self.PYTH_MAGIC:
            raise RuntimeError(f'Wrong magic {magic} in account {acct_addr}')

        version = unpack(self.base_account_layout, data, 'ver')
        if not version in self.SUPPORTED_VERSIONS:
            raise RuntimeError(f'Pyth.Network version not supported: {version}')

        return data


    def read_pyth_acct_data(self, acc_addrs: Union[List[PublicKey], PublicKey]):
        """
        Method is possible to read one or more account data from blockchain
        Given PublicKey as argument, method will return account data as bytes or None in case if account not found
            OR throw error otherwise (e. g. wrong account data format)
        Given list PublicKeys as argument, method will return mapping of account addresses to bytes or Nones (for not found accounts) 
            OR throw error otherwise  (e. g. wrong account data format)
        """

        response = None
        if isinstance(acc_addrs, PublicKey):
            response = self.client.get_account_info(acc_addrs)
        elif isinstance(acc_addrs, list):
            acc_addrs = [ str(addr) for addr in acc_addrs ]
            response = self.client._provider.make_request('getMultipleAccounts', acc_addrs)
        else:
            raise Exception(f'Unsupported argument to read_pyth_acct_data: {acc_addrs}')

        result = response.get('result', None)
        if result is None:
            raise RuntimeError(f'Failed to retrieve data for account(s): {acc_addrs}')

        acct_values = result.get("value", None)
        if acct_values is None:
            raise RuntimeError(f"Reading pyth account(s):'value' field is absent in result")

        if isinstance(acc_addrs, PublicKey):
            # One PublicKey given
            return self.parse_pyth_account_data(acc_addrs, acct_values)
        
        # Several accounts given
        if not isinstance(acct_values, list) or len(acct_values) != len(acc_addrs):
            raise RuntimeError(f'Wrong result.value field in response to getMultipleAccounts')

        return { acct_addr: self.parse_pyth_account_data(acct_addr, acct_value) for acct_addr, acct_value in zip(acc_addrs, acct_values) }


    def parse_mapping_account(self, acc_addr: PublicKey):
        products = []
        while acc_addr != SYS_PROGRAM_ID:
            data = self.read_pyth_acct_data(acc_addr)
            num_products = unpack(self.mapping_account_layout, data, 'num_products')
            acc_addr = unpack(self.mapping_account_layout, data, 'next')
            for i in range(num_products):
                products.append(unpack(self.mapping_account_layout, data, 'product', i))
        return products


    def parse_prod_account(self, acc_data: bytes):
        return {
            'price_acc': unpack(self.product_account_layout, acc_data, 'price_acc'),
            'attrs': unpack(self.product_account_layout, acc_data, 'attrs')
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
        self.info('Start updating Pyth.Network mapping data...')
        product_accts = self.parse_mapping_account(mapping_acc)
        products = self.read_pyth_acct_data(product_accts)
        for acct_addr, product_data in products.items():
            if product_data is None:
                self.warning(f'Failed to read product account: {acct_addr}')
                continue

            try:
                product = self.parse_prod_account(product_data)
                symbol = product['attrs']['symbol']
                self.info(f'Product account {acct_addr}: {symbol}')
                self.price_accounts[symbol] = product['price_acc']
            except Exception as err:
                self.warning(f'Failed to parse product account data {acct_addr} : {err}')
        self.info('Pyth.Network update finished.\n\n\n')


    def get_price(self, symbol):
        """
        Return price data given product symbol.
        Throws exception if symbol is absent in preloaded product map
        or error occured when loading/parsing price account
        """
        return self.parse_price_account(self.price_accounts[symbol])
