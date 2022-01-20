# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import copy
import eth_utils
import json
import threading
import traceback
import unittest
import time

from logged_groups import logged_group

from ..common.utils import build_http_response
from ..http.codes import httpStatusCodes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from solana.account import Account as sol_Account
from solana.rpc.api import Client as SolanaClient, SendTransactionError as SolanaTrxError
from typing import List, Tuple, Optional
from web3 import Web3

from .solana_rest_api_tools import getAccountInfo, call_signed, neon_config_load, \
    get_token_balance_or_airdrop, estimate_gas
from ..common_neon.address import EthereumAddress
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.errors import EthereumError
from ..common_neon.eth_proto import Trx as EthTrx
from ..core.acceptor.pool import proxy_id_glob
from ..environment import neon_cli, solana_cli, SOLANA_URL, MINIMAL_GAS_PRICE
from ..indexer.indexer_db import IndexerDB
from ..indexer.utils import NeonTxInfo

modelInstanceLock = threading.Lock()
modelInstance = None

NEON_PROXY_PKG_VERSION = '0.5.4-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'


@logged_group("neon.proxy")
class EthereumModel:
    def __init__(self):
        self.signer = self.get_solana_account()
        self.client = SolanaClient(SOLANA_URL)

        self.db = IndexerDB(self.client)

        with proxy_id_glob.get_lock():
            self.proxy_id = proxy_id_glob.value
            proxy_id_glob.value += 1
        self.debug("worker id {}".format(self.proxy_id))

        neon_config_load(self)


    @staticmethod
    def get_solana_account() -> Optional[sol_Account]:
        solana_account: Optional[sol_Account] = None
        res = solana_cli().call('config', 'get')
        substr = "Keypair Path: "
        path = ""
        for line in res.splitlines():
            if line.startswith(substr):
                path = line[len(substr):].strip()
        if path == "":
            raise Exception("cannot get keypair path")

        with open(path.strip(), mode='r') as file:
            pk = (file.read())
            nums = list(map(int, pk.strip("[] \n").split(',')))
            nums = nums[0:32]
            values = bytes(nums)
            solana_account = sol_Account(values)
        return solana_account

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
        return hex(MINIMAL_GAS_PRICE)

    def eth_estimateGas(self, param):
        try:
            caller_id = param.get('from', "0x0000000000000000000000000000000000000000")
            contract_id = param.get('to', "deploy")
            data = param.get('data', "None")
            value = param.get('value', "")
            return estimate_gas(self.client, self.signer, contract_id, EthereumAddress(caller_id), data, value)
        except Exception as err:
            self.debug("Exception on eth_estimateGas: %s", err)
            raise

    def __repr__(self):
        return str(self.__dict__)

    def process_block_tag(self, tag):
        if tag == "latest":
            block_number = self.db.get_latest_block_height()
        elif tag in ('earliest', 'pending'):
            raise Exception("Invalid tag {}".format(tag))
        elif isinstance(tag, str):
            block_number = int(tag, 16)
        elif isinstance(tag, int):
            block_number = tag
        else:
            raise Exception(f'Failed to parse block tag: {tag}')
        return block_number

    def eth_blockNumber(self):
        height = self.db.get_latest_block_height()
        self.debug("eth_blockNumber %s", hex(height))
        return hex(height)

    def eth_getBalance(self, account, tag):
        """account - address to check for balance.
           tag - integer block number, or the string "latest", "earliest" or "pending"
        """
        eth_acc = EthereumAddress(account)
        self.debug('eth_getBalance: %s %s', account, eth_acc)
        balance = get_token_balance_or_airdrop(self.client, self.signer, eth_acc)

        return hex(balance * eth_utils.denoms.gwei)

    def eth_getLogs(self, obj):
        fromBlock = None
        toBlock = None
        address = None
        topics = None
        blockHash = None

        if 'fromBlock' in obj and obj['fromBlock'] != '0':
            fromBlock = self.process_block_tag(obj['fromBlock'])
        if 'toBlock' in obj and obj['toBlock'] != 'latest':
            toBlock = self.process_block_tag(obj['toBlock'])
        if 'address' in obj:
           address = obj['address']
        if 'topics' in obj:
           topics = obj['topics']
        if 'blockHash' in obj:
           blockHash = obj['blockHash']

        return self.db.get_logs(fromBlock, toBlock, address, topics, blockHash)

    def getBlockBySlot(self, slot, full):
        block = self.db.get_full_block_by_slot(slot, commitment='confirmed')
        if block.slot is None:
            return None

        transactions = []
        gasUsed = 0
        trx_index = 0
        for signature in block.signs:
            tx = self.db.get_tx_by_sol_sign(signature, commitment='confirmed')
            if not tx:
                continue

            trx_receipt = self._getTransactionReceipt(tx)
            if trx_receipt is not None:
                gasUsed += int(trx_receipt['gasUsed'], 16)
            if full:
                trx = self._getTransaction(tx)
                if trx is not None:
                    trx['transactionIndex'] = hex(trx_index)
                    trx_index += 1
                    transactions.append(trx)
            else:
                transactions.append(tx.neon_tx.sign)

        ret = {
            "gasUsed": hex(gasUsed),
            "hash": block.hash,
            "number": hex(slot),
            "parentHash": block.parent_hash,
            "timestamp": hex(block.time),
            "transactions": transactions,
            "logsBloom": '0x'+'0'*512,
            "gasLimit": '0x6691b7',
        }
        return ret

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
            self.debug(f"Neon-cli failed to execute: {err}")
            return '0x00'

    def eth_getBlockByHash(self, block_hash, full):
        """Returns information about a block by hash.
            block_hash - Hash of a block.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block_hash = block_hash.lower()
        slot = self.db.get_block_by_hash(block_hash).slot
        if slot is None:
            self.debug("Not found block by hash %s", block_hash)
            return None
        ret = self.getBlockBySlot(slot, full)
        if ret is not None:
            self.debug("eth_getBlockByHash: %s", json.dumps(ret, indent=3))
        else:
            self.debug("Not found block by hash %s", block_hash)
        return ret

    def eth_getBlockByNumber(self, tag, full):
        """Returns information about a block by block number.
            tag - integer of a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block_number = self.process_block_tag(tag)
        slot = self.db.get_block_by_height(block_number).slot
        if slot is None:
            self.debug("Not found block by number %s", tag)
            return None
        ret = self.getBlockBySlot(slot, full)
        if ret is not None:
            self.debug("eth_getBlockByNumber: %s", json.dumps(ret, indent=3))
        else:
            self.debug("Not found block by number %s", tag)
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
        except Exception as err:
            self.debug("eth_call %s", err)
            raise

    def eth_getTransactionCount(self, account, tag):
        self.debug('eth_getTransactionCount: %s', account)
        try:
            acc_info = getAccountInfo(self.client, EthereumAddress(account))
            return hex(int.from_bytes(acc_info.trx_count, 'little'))
        except Exception as err:
            print("Can't get account info: %s"%err)
            return hex(0)

    def _getTransactionReceipt(self, tx):
        result = {
            "transactionHash": tx.neon_tx.sign,
            "transactionIndex": hex(0),
            "blockHash": tx.block.hash,
            "blockNumber": hex(tx.block.height),
            "from": tx.neon_tx.addr,
            "to": tx.neon_tx.to_addr,
            "gasUsed": tx.neon_res.gas_used,
            "cumulativeGasUsed": tx.neon_res.gas_used,
            "contractAddress": tx.neon_tx.contract,
            "logs": tx.neon_res.logs,
            "status": tx.neon_res.status,
            "logsBloom":"0x"+'0'*512
        }

        self.debug('RESULT: %s', json.dumps(result, indent=3))
        return result

    def eth_getTransactionReceipt(self, trxId):
        self.debug('eth_getTransactionReceipt: %s', trxId)

        neon_sign = trxId.lower()
        tx = self.db.get_tx_by_neon_sign(neon_sign, commitment='confirmed')
        if not tx:
            self.debug("Not found receipt")
            return None
        return self._getTransactionReceipt(tx)

    def _getTransaction(self, tx):
        t = tx.neon_tx
        ret = {
            "blockHash": tx.block.hash,
            "blockNumber": hex(tx.block.height),
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

        self.debug("_getTransaction: %s", json.dumps(ret, indent=3))
        return ret

    def eth_getTransactionByHash(self, trxId):
        self.debug('eth_getTransactionByHash: %s', trxId)

        neon_sign = trxId.lower()
        tx = self.db.get_tx_by_neon_sign(neon_sign)
        if tx is None:
            self.debug("Not found receipt")
            return None
        return self._getTransaction(tx)

    def eth_getCode(self, param,  param1):
        return "0x01"

    def eth_sendTransaction(self, trx):
        self.debug("eth_sendTransaction")
        self.debug("eth_sendTransaction: type(trx):%s", type(trx))
        self.debug("eth_sendTransaction: str(trx):%s", str(trx))
        self.debug("eth_sendTransaction: trx=%s", json.dumps(trx, cls=JsonEncoder, indent=3))
        raise Exception("eth_sendTransaction is not supported. please use eth_sendRawTransaction")

    def eth_sendRawTransaction(self, rawTrx):
        self.debug('eth_sendRawTransaction rawTrx=%s', rawTrx)
        trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        self.debug("%s", json.dumps(trx.as_dict(), cls=JsonEncoder, indent=3))
        if trx.gasPrice < MINIMAL_GAS_PRICE:
            raise Exception("The transaction gasPrice is less then the minimum allowable value ({}<{})".format(trx.gasPrice, MINIMAL_GAS_PRICE))

        eth_signature = '0x' + bytes(Web3.keccak(bytes.fromhex(rawTrx[2:]))).hex()

        sender = trx.sender()
        self.debug('Eth Sender: %s', sender)
        self.debug('Eth Signature: %s', trx.signature().hex())
        self.debug('Eth Hash: %s', eth_signature)

        nonce = int(self.eth_getTransactionCount('0x' + sender, None), base=16)

        self.debug('Eth Sender trx nonce in solana: %s', nonce)
        self.debug('Eth Sender trx nonce in transaction: %s', trx.nonce)

        if (int(nonce) != int(trx.nonce)):
            raise EthereumError(-32002, 'Verifying nonce before send transaction: Error processing Instruction 1: invalid program argument'
                                .format(int(nonce), int(trx.nonce)),
                                {
                                    'logs': [
                                        '/src/entrypoint.rs Invalid Ethereum transaction nonce: acc {}, trx {}'.format(nonce, trx.nonce),
                                    ]
                                })
        try:
            neon_res, signature = call_signed(self.signer, self.client, trx, steps=250)
            self.debug('Transaction signature: %s %s', signature, eth_signature)
            neon_tx = NeonTxInfo()
            neon_tx.init_from_eth_tx(trx)
            self.db.submit_transaction(neon_tx, neon_res, [], commitment='confirmed')
            return eth_signature

        except SolanaTrxError as err:
            self._log_transaction_error(err)
            raise
        except EthereumError as err:
            self.debug("eth_sendRawTransaction EthereumError:%s", err)
            raise
        except Exception as err:
            self.debug("eth_sendRawTransaction type(err):%s, Exception:%s", type(err), err)
            raise

    def _log_transaction_error(self, error: SolanaTrxError):
        result = copy.deepcopy(error.result)
        logs = result.get("data", {}).get("logs", [])
        result.get("data", {}).update({"logs": ["\n\t" + log for log in logs]})
        log_msg = str(result).replace("\\n\\t", "\n\t")
        self.error(f"Got SendTransactionError: {log_msg}")


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


@logged_group("neon.test_cases")
class SolanaContractTests(unittest.TestCase):

    def setUp(self):
        self.model = EthereumModel()
        self.owner = '0xc1566af4699928fdf9be097ca3dc47ece39f8f8e'
        self.token1 = '0x49a449cd7fd8fbcf34d103d98f2c05245020e35b'

    def getBalance(self, account):
        return int(self.model.eth_getBalance(account, 'latest'), 16)

    def getBlockNumber(self):
        return int(self.model.eth_blockNumber(), 16)

    def getTokenBalance(self, token, account):
        return self.model.contracts[token].balances.get(account, 0)

    def test_transferFunds(self):
        (sender, receiver, amount) = (self.owner, '0x8d900bfa2353548a4631be870f99939575551b60', 123*10**18)
        senderBalance = self.getBalance(sender)
        receiverBalance = self.getBalance(receiver)
        blockNumber = self.getBlockNumber()

        receiptId = self.model.eth_sendRawTransaction('0xf8730a85174876e800825208948d900bfa2353548a4631be870f99939575551b608906aaf7c8516d0c0000808602e92be91e86a040a2a5d73931f66185e8526f09c4d0dc1f389c1b9fcd5e37a012839e6c5c70f0a00554615806c3fa7dc7c8096b3bfed5a29354045e56982bdf3ee11f649e53d51e')
        self.debug('ReceiptId:', receiptId)

        self.assertEqual(self.getBalance(sender), senderBalance - amount)
        self.assertEqual(self.getBalance(receiver), receiverBalance + amount)
        self.assertEqual(self.getBlockNumber(), blockNumber+1)

        receipt = self.model.eth_getTransactionReceipt(receiptId)
        self.debug('Receipt:', receipt)

        block = self.model.eth_getBlockByNumber(receipt['blockNumber'], False)
        self.debug('Block:', block)

        self.assertTrue(receiptId in block['transactions'])

    def test_transferTokens(self):
        (token, sender, receiver, amount) = ('0xcf73021fde8654e64421f67372a47aa53c4341a8', '0x324726ca9954ed9bd567a62ae38a7dd7b4eaad0e', '0xb937ad32debafa742907d83cb9749443160de0c4', 32)
        senderBalance = self.getTokenBalance(token, sender)
        receiverBalance = self.getTokenBalance(token, receiver)
        blockNumber = self.getBlockNumber()


        receiptId = self.model.eth_sendRawTransaction('0xf8b018850bdfd63e00830186a094b80102fd2d3d1be86823dd36f9c783ad0ee7d89880b844a9059cbb000000000000000000000000cac68f98c1893531df666f2d58243b27dd351a8800000000000000000000000000000000000000000000000000000000000000208602e92be91e86a05ed7d0093a991563153f59c785e989a466e5e83bddebd9c710362f5ee23f7dbaa023a641d304039f349546089bc0cb2a5b35e45619fd97661bd151183cb47f1a0a')
        self.debug('ReceiptId:', receiptId)

        self.assertEqual(self.getTokenBalance(token, sender), senderBalance - amount)
        self.assertEqual(self.getTokenBalance(token, receiver), receiverBalance + amount)

        receipt = self.model.eth_getTransactionReceipt(receiptId)
        self.debug('Receipt:', receipt)

        block = self.model.eth_getBlockByNumber(receipt['blockNumber'], False)
        self.debug('Block:', block)

        self.assertTrue(receiptId in block['transactions'])


@logged_group("neon.proxy")
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
        except SolanaTrxError as err:
            # traceback.print_exc()
            response['error'] = err.result
        except EthereumError as err:
            # traceback.print_exc()
            response['error'] = err.getError()
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.warning('Exception on process request. ' +
                           f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            response['error'] = {'code': -32000, 'message': str(err)}

        return response

    def handle_request(self, request: HttpParser) -> None:
        if request.method == b'OPTIONS':
            self.client.queue(memoryview(build_http_response(
                httpStatusCodes.OK, body=None,
                headers={
                    b'Access-Control-Allow-Origin': b'*',
                    b'Access-Control-Allow-Methods': b'POST, GET, OPTIONS',
                    b'Access-Control-Allow-Headers': b'Content-Type',
                    b'Access-Control-Max-Age': b'86400'
                })))
            return
        start_time = time.time()
        self.debug('<<< %s 0x%x %s', threading.get_ident(), id(self.model), request.body.decode('utf8'))
        response = None

        try:
            request = json.loads(request.body)
            self.debug(f'Request payload: {request}')
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
            traceback.print_exc()
            response = {'jsonrpc': '2.0', 'error': {'code': -32000, 'message': str(err)}}

        resp_time_ms = (time.time() - start_time)*1000  # convert this into milliseconds
        self.debug('>>> %s 0x%0x %s %s resp_time_ms= %s', threading.get_ident(), id(self.model), json.dumps(response),
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

