# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import eth_utils
import json
import threading
import traceback
import time
import hashlib
import multiprocessing

from logged_groups import logged_group, logging_context

from ..common.utils import build_http_response
from ..http.codes import httpStatusCodes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from typing import List, Tuple

from .solana_rest_api_tools import neon_config_load
from ..common_neon.transaction_sender import NeonTxSender
from ..common_neon.solana_interactor import SolanaInteractor, SolTxError
from ..common_neon.address import EthereumAddress
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.errors import EthereumError, PendingTxError
from ..common_neon.estimate import GasEstimate
from ..common_neon.utils import SolanaBlockInfo
from ..environment import SOLANA_URL, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, EVM_STEP_COUNT
from ..environment import neon_cli
from ..memdb.memdb import MemDB
from .gas_price_calculator import GasPriceCalculator
from ..common_neon.eth_proto import Trx as EthTrx

modelInstanceLock = threading.Lock()
modelInstance = None

NEON_PROXY_PKG_VERSION = '0.6.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'


@logged_group("neon.Proxy")
class EthereumModel:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self):
        self._solana = SolanaInteractor(SOLANA_URL)
        self._db = MemDB(self._solana)

        if PP_SOLANA_URL == SOLANA_URL:
            self.gas_price_calculator = GasPriceCalculator(self._solana, PYTH_MAPPING_ACCOUNT)
        else:
            self.gas_price_calculator = GasPriceCalculator(SolanaInteractor(PP_SOLANA_URL), PYTH_MAPPING_ACCOUNT)
        self.gas_price_calculator.update_mapping()
        self.gas_price_calculator.try_update_gas_price()

        with self.proxy_id_glob.get_lock():
            self.proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        self.debug(f"Worker id {self.proxy_id}")

        neon_config_load(self)

    def neon_proxy_version(self):
        return 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION

    def web3_clientVersion(self):
        neon_config_load(self)
        return self.neon_config_dict['web3_clientVersion']

    def eth_chainId(self):
        neon_config_load(self)
        # NEON_CHAIN_ID is a string in decimal form
        return hex(int(self.neon_config_dict['NEON_CHAIN_ID']))

    def neon_cli_version(self):
        return neon_cli().version()

    def net_version(self):
        neon_config_load(self)
        # NEON_CHAIN_ID is a string in decimal form
        return self.neon_config_dict['NEON_CHAIN_ID']

    def eth_gasPrice(self):
        return hex(int(self.gas_price_calculator.get_suggested_gas_price()))

    def eth_estimateGas(self, param):
        try:
            calculator = GasEstimate(param, self._solana)
            return calculator.estimate()

        except EthereumError:
            raise
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Exception on eth_estimateGas: {err}: {err_tb}")
            raise

    def __repr__(self):
        return str(self.__dict__)

    def process_block_tag(self, tag):
        if tag == "latest":
            block = self._db.get_latest_block()
        elif tag in ('earliest', 'pending'):
            raise Exception("Invalid tag {}".format(tag))
        elif isinstance(tag, str):
            block = SolanaBlockInfo(slot=int(tag, 16))
        elif isinstance(tag, int):
            block = SolanaBlockInfo(slot=tag)
        else:
            raise Exception(f'Failed to parse block tag: {tag}')
        return block

    def eth_blockNumber(self):
        slot = self._db.get_latest_block_slot()
        return hex(slot)

    def eth_getBalance(self, account, tag):
        """account - address to check for balance.
           tag - integer block number, or the string "latest", "earliest" or "pending"
        """
        self.debug(f'eth_getBalance: {account}')
        try:
            acc_info = self._solana.get_account_info_layout(EthereumAddress(account))
            if acc_info is None:
                return hex(0)

            return hex(acc_info.balance)
        except Exception as err:
            self.debug(f"eth_getBalance: Can't get account info: {err}")
            return hex(0)

    def eth_getLogs(self, obj):
        def to_list(items):
            if isinstance(items, str):
                return [items.lower()]
            elif isinstance(items, list):
                return list(set([item.lower() for item in items if isinstance(item, str)]))
            return []

        from_block = None
        to_block = None
        addresses = []
        topics = []
        block_hash = None

        if 'fromBlock' in obj and obj['fromBlock'] != '0':
            from_block = self.process_block_tag(obj['fromBlock']).slot
        if 'toBlock' in obj and obj['toBlock'] != 'latest':
            to_block = self.process_block_tag(obj['toBlock']).slot
        if 'address' in obj:
            addresses = to_list(obj['address'])
        if 'topics' in obj:
            topics = to_list(obj['topics'])
        if 'blockHash' in obj:
            block_hash = obj['blockHash']

        return self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def getBlockBySlot(self, block: SolanaBlockInfo, full, skip_transaction):
        if not block.time:
            block = self._db.get_full_block_by_slot(block.slot)
            if not block.time:
                return None

        sign_list = []
        gas_used = 0
        tx_index = 0
        if skip_transaction:
            tx_list = []
        else:
            tx_list = self._db.get_tx_list_by_sol_sign(block.finalized, block.signs)

        for tx in tx_list:
            gas_used += int(tx.neon_res.gas_used, 16)

            if full:
                receipt = self._getTransaction(tx)
                receipt['transactionIndex'] = hex(tx_index)
                tx_index += 1
                sign_list.append(receipt)
            else:
                sign_list.append(tx.neon_tx.sign)

        result = {
            "gasUsed": hex(gas_used),
            "hash": block.hash,
            "number": hex(block.slot),
            "parentHash": block.parent_hash,
            "timestamp": hex(block.time),
            "transactions": sign_list,
            "logsBloom": '0x'+'0'*512,
            "gasLimit": '0x6691b7',
        }
        return result

    def eth_getStorageAt(self, account, position, block_identifier):
        '''Retrieves storage data by given position
        Currently supports only 'latest' block
        '''
        if block_identifier != "latest":
            self.debug(f"Block type '{block_identifier}' is not supported yet")
            raise RuntimeError(f"Not supported block identifier: {block_identifier}")

        try:
            value = neon_cli().call('get-storage-at', account, position)
            return value
        except Exception as err:
            self.error(f"eth_getStorageAt: Neon-cli failed to execute: {err}")
            return '0x00'

    def eth_getBlockByHash(self, block_hash, full):
        """Returns information about a block by hash.
            block_hash - Hash of a block.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block_hash = block_hash.lower()
        block = self._db.get_block_by_hash(block_hash)
        if block.slot is None:
            self.debug("Not found block by hash %s", block_hash)
            return None
        ret = self.getBlockBySlot(block, full, False)
        return ret

    def eth_getBlockByNumber(self, tag, full):
        """Returns information about a block by block number.
            tag - integer of a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block = self.process_block_tag(tag)
        if block.slot is None:
            self.debug(f"Not found block by number {tag}")
            return None
        ret = self.getBlockBySlot(block, full, tag == 'latest')
        return ret

    def eth_call(self, obj, tag):
        """Executes a new message call immediately without creating a transaction on the block chain.
           Parameters
            obj - The transaction call object
                from: DATA, 20 Bytes - (optional) The address the transaction is sent from.
                to: DATA, 20 Bytes - The address the transaction is directed to.
                gas: QUANTITY - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
                gasPrice: QUANTITY - (optional) Integer of the gasPrice used for each paid gas
                value: QUANTITY - (optional) Integer of the value sent with this transaction
                data: DATA - (optional) Hash of the method signature and encoded parameters. For details see Ethereum Contract ABI in the Solidity documentation
            tag - integer block number, or the string "latest", "earliest" or "pending", see the default block parameter
        """
        if not obj['data']: raise Exception("Missing data")
        try:
            caller_id = obj.get('from', "0x0000000000000000000000000000000000000000")
            contract_id = obj.get('to', 'deploy')
            data = obj.get('data', "None")
            value = obj.get('value', '')
            return "0x"+call_emulated(contract_id, caller_id, data, value)['result']
        except EthereumError:
            raise
        except Exception as err:
            self.error("eth_call Exception %s", err)
            raise

    def eth_getTransactionCount(self, account, tag):
        self.debug('eth_getTransactionCount: %s', account)
        try:
            acc_info = self._solana.get_account_info_layout(EthereumAddress(account))
            return hex(acc_info.trx_count)
        except Exception as err:
            self.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    def _getTransactionReceipt(self, tx):
        result = {
            "transactionHash": tx.neon_tx.sign,
            "transactionIndex": hex(0),
            "blockHash": tx.neon_res.block_hash,
            "blockNumber": hex(tx.neon_res.slot),
            "from": tx.neon_tx.addr,
            "to": tx.neon_tx.to_addr,
            "gasUsed": tx.neon_res.gas_used,
            "cumulativeGasUsed": tx.neon_res.gas_used,
            "contractAddress": tx.neon_tx.contract,
            "logs": tx.neon_res.logs,
            "status": tx.neon_res.status,
            "logsBloom": "0x"+'0'*512
        }

        return result

    def eth_getTransactionReceipt(self, trxId):
        self.debug('eth_getTransactionReceipt: %s', trxId)

        neon_sign = trxId.lower()
        tx = self._db.get_tx_by_neon_sign(neon_sign)
        if not tx:
            self.debug("Not found receipt")
            return None
        return self._getTransactionReceipt(tx)

    def _getTransaction(self, tx):
        t = tx.neon_tx
        r = tx.neon_res

        result = {
            "blockHash": r.block_hash,
            "blockNumber": hex(r.slot),
            "hash": t.sign,
            "transactionIndex": hex(0),
            "from": t.addr,
            "nonce":  t.nonce,
            "gasPrice": t.gas_price,
            "gas": t.gas_limit,
            "to": t.to_addr,
            "value": t.value,
            "input": t.calldata,
            "v": t.v,
            "r": t.r,
            "s": t.s,
        }

        return result

    def eth_getTransactionByHash(self, trxId):
        self.debug('eth_getTransactionByHash: %s', trxId)

        neon_sign = trxId.lower()
        tx = self._db.get_tx_by_neon_sign(neon_sign)
        if tx is None:
            self.debug("Not found receipt")
            return None
        return self._getTransaction(tx)

    def eth_getCode(self, account, _tag):
        account = account.lower()
        return self._db.get_contract_code(account)

    def eth_sendTransaction(self, trx):
        self.debug(f"eth_sendTransaction type(trx): {type(trx)}, str(trx): {str(trx)}")
        raise RuntimeError("eth_sendTransaction is not supported. please use eth_sendRawTransaction")

    def eth_sendRawTransaction(self, rawTrx):
        trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        self.debug(f"{json.dumps(trx.as_dict(), cls=JsonEncoder, sort_keys=True)}")
        min_gas_price = self.gas_price_calculator.get_min_gas_price()

        if trx.gasPrice < min_gas_price:
            raise RuntimeError("The transaction gasPrice is less than the minimum allowable value" +
                               f"({trx.gasPrice}<{min_gas_price})")

        user_balance = int(self.eth_getBalance('0x' + trx.sender(), 'latest'), 16)
        fee = trx.gasPrice * trx.gasLimit
        required_balance = fee + trx.value
        if user_balance < required_balance:
            raise RuntimeError("The account balance is less than required: " +
                               f"Account {trx.sender()}; balance = {user_balance}; " +
                               f"gasPrice = {trx.gasPrice}; gasLimit = {trx.gasLimit}; " +
                               f"fee = {fee}; value = {trx.value}; " +
                               f"required_balance = {required_balance}; ")

        eth_signature = '0x' + trx.hash_signed().hex()

        try:
            tx_sender = NeonTxSender(self._db, self._solana, trx, steps=EVM_STEP_COUNT)
            tx_sender.execute()
            return eth_signature

        except PendingTxError as err:
            self.debug(f'{err}')
            return eth_signature
        except SolTxError as err:
            err_msg = json.dumps(err.result, indent=3)
            self.error(f"Got SendTransactionError: {err_msg}")
            raise
        except EthereumError as err:
            # self.debug(f"eth_sendRawTransaction EthereumError: {err}")
            raise
        except Exception as err:
            # self.error(f"eth_sendRawTransaction type(err): {type(err}}, Exception: {err}")
            raise


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


@logged_group("neon.Proxy")
class SolanaProxyPlugin(HttpWebServerBasePlugin):
    """Extend in-built Web Server to add Reverse Proxy capabilities.
    """

    SOLANA_PROXY_LOCATION: str = r'/solana$'
    SOLANA_PROXY_PASS = [
        b'http://localhost:8545/'
    ]

    def __init__(self, *args):
        HttpWebServerBasePlugin.__init__(self, *args)
        self.model = SolanaProxyPlugin.getModel()

    @classmethod
    def getModel(cls):
        global modelInstanceLock
        global modelInstance
        with modelInstanceLock:
            if modelInstance is None:
                modelInstance = EthereumModel()
            return modelInstance

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, SolanaProxyPlugin.SOLANA_PROXY_LOCATION),
            (httpProtocolTypes.HTTPS, SolanaProxyPlugin.SOLANA_PROXY_LOCATION)
        ]

    def process_request(self, request):
        response = {
            'jsonrpc': '2.0',
            'id': request.get('id', None),
        }
        try:
            if not hasattr(self.model, request['method']):
                response['error'] = {'code': -32000, 'message': f'method {request["method"]} is not supported'}
            else:
                method = getattr(self.model, request['method'])
                params = request.get('params', [])
                response['result'] = method(*params)
        except SolTxError as err:
            # traceback.print_exc()
            response['error'] = err.error
        except EthereumError as err:
            # traceback.print_exc()
            response['error'] = err.getError()
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error('Exception on process request. ' +
                       f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            response['error'] = {'code': -32000, 'message': str(err)}

        return response

    def handle_request(self, request: HttpParser) -> None:
        unique_req_id = self.get_unique_id()
        with logging_context(req_id=unique_req_id):
            self.handle_request_impl(request)
            self.info("Request processed")

    @staticmethod
    def get_unique_id():
        return hashlib.md5((time.time_ns()).to_bytes(16, 'big')).hexdigest()[:7]

    def handle_request_impl(self, request: HttpParser) -> None:
        if request.method == b'OPTIONS':
            self._client.queue(memoryview(build_http_response(
                httpStatusCodes.OK, body=None,
                headers={
                    b'Access-Control-Allow-Origin': b'*',
                    b'Access-Control-Allow-Methods': b'POST, GET, OPTIONS',
                    b'Access-Control-Allow-Headers': b'Content-Type',
                    b'Access-Control-Max-Age': b'86400'
                })))
            return
        start_time = time.time()
        self.info('handle_request <<< %s 0x%x %s', threading.get_ident(), id(self.model), request.body.decode('utf8'))
        response = None

        try:
            request = json.loads(request.body)
            if isinstance(request, list):
                response = []
                if len(request) == 0:
                    raise Exception("Empty batch request")
                for r in request:
                    response.append(self.process_request(r))
            elif isinstance(request, object):
                response = self.process_request(request)
            else:
                raise Exception("Invalid request")
        except Exception as err:
            # traceback.print_exc()
            response = {'jsonrpc': '2.0', 'error': {'code': -32000, 'message': str(err)}}

        resp_time_ms = (time.time() - start_time)*1000  # convert this into milliseconds
        self.info('handle_request >>> %s 0x%0x %s %s resp_time_ms= %s',
                  threading.get_ident(),
                  id(self.model),
                  json.dumps(response),
                  request.get('method', '---'),
                  resp_time_ms)

        self.client.queue(memoryview(build_http_response(
            httpStatusCodes.OK, body=json.dumps(response).encode('utf8'),
            headers={
                b'Content-Type': b'application/json',
                b'Access-Control-Allow-Origin': b'*',
            })))

    def on_websocket_open(self) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def on_websocket_close(self) -> None:
        pass
