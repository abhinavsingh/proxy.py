# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import List, Tuple
import json
import unittest

import solana
from solana.account import Account as sol_Account
from ..common.utils import socket_connection, text_, build_http_response
from ..http.codes import httpStatusCodes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from .eth_proto import Trx as EthTrx
from solana.rpc.api import Client as SolanaClient
from sha3 import keccak_256, shake_256
import base58
import traceback
import threading
from .solana_rest_api_tools import EthereumAddress,  create_account_with_seed, evm_loader_id, getTokens, \
    getAccountInfo, solana_cli, call_signed, solana_url, call_emulated, \
    Trx, deploy_contract, EthereumError, create_collateral_pool_address, getTokenAddr, STORAGE_SIZE
from web3 import Web3
import logging
from ..core.acceptor.pool import signatures_glob, vrs_glob, contract_address_glob, eth_sender_glob, proxy_id_glob
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

modelInstanceLock = threading.Lock()
modelInstance = None

chainId = os.environ.get("NEON_CHAIN_ID", "0x6e")    # default value 110
EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))

class PermanentAccounts:
    def __init__(self, client, signer, proxy_id):
        self.operator = signer.public_key()
        self.operator_token = getTokenAddr(self.operator)

        proxy_id_bytes = proxy_id.to_bytes((proxy_id.bit_length() + 7) // 8, 'big')
        signer_public_key_bytes = bytes(signer.public_key())

        storage_seed = shake_256(b"storage" + proxy_id_bytes + signer_public_key_bytes).hexdigest(16)
        storage_seed = bytes(storage_seed, 'utf8')
        self.storage = create_account_with_seed(client, funding=signer, base=signer, seed=storage_seed, storage_size=STORAGE_SIZE)

        holder_seed = shake_256(b"holder" + proxy_id_bytes + signer_public_key_bytes).hexdigest(16)
        holder_seed = bytes(holder_seed, 'utf8')
        self.holder = create_account_with_seed(client, funding=signer, base=signer, seed=holder_seed, storage_size=STORAGE_SIZE)

        collateral_pool_index = proxy_id % 4
        self.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')
        self.collateral_pool_address = create_collateral_pool_address(collateral_pool_index)


class EthereumModel:
    def __init__(self):
        # Initialize user account
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
            self.signer = sol_Account(values)

        self.client = SolanaClient(solana_url)
        self.signatures = signatures_glob
        self.vrs = vrs_glob
        self.eth_sender = eth_sender_glob
        self.contract_address = contract_address_glob

        with proxy_id_glob.get_lock():
            self.proxy_id = proxy_id_glob.value
            proxy_id_glob.value += 1
        logger.debug("worker id {}".format(self.proxy_id))

        self.perm_accs = PermanentAccounts(self.client, self.signer, self.proxy_id)
        pass

    def eth_chainId(self):
        return chainId

    def net_version(self):
        return str(int(chainId,base=16))

    def eth_gasPrice(self):
        return hex(15*10**9)

    def eth_estimateGas(self, param):
        try:
            caller_id = param['from'] if 'from' in param else "0x0000000000000000000000000000000000000000"
            contract_id = param['to'] if 'to' in param else "deploy"
            data = param['data'] if 'data' in param else "None"
            value = param['value'] if 'value' in param else ""
            result = call_emulated(contract_id, caller_id, data, value)
            return result['used_gas']+EXTRA_GAS
        except Exception as err:
            logger.debug("Exception on eth_estimateGas: %s", err)
            raise

    def __repr__(self):
        return str(self.__dict__)

    def eth_blockNumber(self):
        slot = self.client.get_slot()['result']
        logger.debug("eth_blockNumber %s", hex(slot))
        return hex(slot)

    def eth_getBalance(self, account, tag):
        """account - address to check for balance.
           tag - integer block number, or the string "latest", "earliest" or "pending"
        """
        eth_acc = EthereumAddress(account)
        logger.debug('eth_getBalance: %s %s', account, eth_acc)
        balance = getTokens(self.client, self.signer, evm_loader_id, eth_acc, self.signer.public_key())

        return hex(balance*10**9)

    def eth_getBlockByHash(self, tag, full):
        return self.eth_getBlockByNumber(tag, full)

    def eth_getBlockByNumber(self, tag, full):
        """Returns information about a block by block number.
            tag - integer of a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        if tag == "latest":
            number = int(self.client.get_slot()["result"])
        elif tag in ('earliest', 'pending'):
            raise Exception("Invalid tag {}".format(tag))
        else:
            number = int(tag, 16)
        response = self.client.get_confirmed_block(number)
        if 'error' in response:
            raise Exception(response['error']['message'])

        block = response['result']
        signatures = [trx['transaction']['signatures'][0] for trx in block['transactions']]
        eth_signatures = []
        for signature in signatures:
            eth_signature = '0x'+keccak_256(base58.b58decode(signature)).hexdigest()
            self.signatures[eth_signature] = signature
            eth_signatures.append(eth_signature)

        return {
            "number": number,
            "gasLimit": "0x6691b7",
            "transactions": eth_signatures,
        }


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
            caller_id = obj['from'] if 'from' in obj else "0x0000000000000000000000000000000000000000"
            contract_id = obj['to']
            data = obj['data'] if 'data' in obj else "None"
            value = obj['value'] if 'value' in obj else ""
            return "0x"+call_emulated(contract_id, caller_id, data, value)['result']
        except Exception as err:
            logger.debug("eth_call %s", err)
            raise

    def eth_getTransactionCount(self, account, tag):
        logger.debug('eth_getTransactionCount: %s', account)
        try:
            acc_info = getAccountInfo(self.client, EthereumAddress(account), self.signer.public_key())
            return hex(int.from_bytes(acc_info.trx_count, 'little'))
        except Exception as err:
            print("Can't get account info: %s"%err)
            return hex(0)

    def eth_getTransactionReceipt(self, trxId):
        receipt = self.signatures.get(trxId, None)
        logger.debug('getTransactionReceipt: %s %s', trxId, receipt)
        if not receipt:
            logger.debug ("Not found receipt")
            return {
            "transactionHash":'0x0',
            "transactionIndex":'0x0',
            "blockHash":'0x0',
            "blockNumber":'0x0',
            "from":'0x0',
            "to":'0x0',
            "gasUsed":'0x0',
            "cumulativeGasUsed":'0x0',
            "contractAddress":'0x0',
            "logs":[],
            "status":"0x0",
            "logsBloom":'0x0'
            }

        trx = self.client.get_confirmed_transaction(receipt)
        logger.debug('RECEIPT: %s', json.dumps(trx, indent=3))
        if trx['result'] is None:
            logger.debug('RESULT is None')
            return None

        logs = []
        status = "0x1"
        gas_used = 0
        log_index = 0
        for inner in (trx['result']['meta']['innerInstructions']):
            for event in inner['instructions']:
                log = base58.b58decode(event['data'])
                instruction = log[:1]
                if (int().from_bytes(instruction, "little") == 7):  # OnEvent evmInstruction code
                    address = log[1:21]
                    count_topics = int().from_bytes(log[21:29], 'little')
                    topics = []
                    pos = 29
                    for _ in range(count_topics):
                        topic_bin = log[pos:pos + 32]
                        topics.append('0x'+topic_bin.hex())
                        pos += 32
                    data = log[pos:]
                    rec = { 'address': '0x'+address.hex(),
                            'topics': topics,
                            'data': '0x'+data.hex(),
                            'transactionLogIndex': hex(0),
                            'transactionIndex': hex(inner['index']),
                            'blockNumber': hex(trx['result']['slot']),
                            'transactionHash': trxId,
                            'logIndex': hex(log_index),
                            'blockHash': '0x%064x'%trx['result']['slot']
                        }
                    logs.append(rec)
                    log_index +=1
                elif int().from_bytes(instruction, "little") == 6:  # OnReturn evmInstruction code
                    if log[1] < 0xd0:
                        status = "0x1"
                    else:
                        status = "0x0"
                    gas_used = int.from_bytes(log[2:10], 'little')

        instruction_data = base58.b58decode(trx['result']['transaction']['message']['instructions'][0]['data'])
        if instruction_data[0] == 0x0c: # Cancel
            status = "0x0"

        block = self.client.get_confirmed_block(trx['result']['slot'])
        # logger.debug('BLOCK: %s', json.dumps(block, indent=3))

        # TODO: it is need to add field "to"
        # instructions = trx['result']['transaction']['message']['instructions']
        # to = ""
        # if len(instructions) >= 2:
        #     data = base58.b58decode(trx['result']['transaction']['message']['instructions'][1]['data'])
        #     if data[0] == 5:   # call_signed
        #         trx_parsed = Trx.fromString(data[86:])
        #         to = '0x'+trx_parsed.toAddress.hex()
        # else:
        #     if self.contract_address.get(trxId) :
        #         to  = self.contract_address.get(trxId)

        # logger.debug('DATA: %s', data.hex())

        result = {
            "transactionHash":trxId,
            "transactionIndex":hex(0),
            "blockHash":'0x%064x'%trx['result']['slot'],
            "blockNumber":hex(trx['result']['slot']),
            "from":'0x'+self.eth_sender[trxId],
            # "to":'',
            "gasUsed":'0x%x' % gas_used,
            "cumulativeGasUsed":'0x%x' % gas_used,
            "contractAddress":self.contract_address.get(trxId),
            "logs": logs,
            "status": status,
            "logsBloom":"0x"+'0'*512
        }
        logger.debug('RESULT: %s', json.dumps(result, indent=3))
        return result

    def eth_getTransactionByHash(self, trxId):
        receipt = self.signatures.get(trxId, None)
        logger.debug('getTransactionReceipt: %s %s', trxId, receipt)
        if not receipt:
            logger.debug ("Not found receipt")
            return {
                "blockHash":'0x0',
                "blockNumber":'0x0',
                "from":'0x0',
                "gas":'0x0',
                "gasPrice":'0x0',
                "hash":'0x0',
                "input":'0x0',
                "nonce":'0x0',
                "to":'0x0',
                "transactionIndex":'0x0',
                "value":'0x0',
                "v":'0x0',
                "r":'0x0',
                "s":'0x0'
            }

        trx = self.client.get_confirmed_transaction(receipt)
        # logger.debug('RECEIPT: %s', json.dumps(trx, indent=3))
        if trx['result'] is None: return None

        block = self.client.get_confirmed_block(trx['result']['slot'])
        # logger.debug('BLOCK: %s', json.dumps(block, indent=3))

        data = base58.b58decode(trx['result']['transaction']['message']['instructions'][0]['data'])
        logger.debug('DATA: %s', data.hex())
        sender =  self.eth_sender[trxId]
        # nonce = int(self.eth_getTransactionCount('0x'+data[sender].hex(), ""), 16)
        nonce = 0
        # if nonce > 0 :
        #     nonce = nonce - 1
        ret = {
            "blockHash":'0x%064x'%trx['result']['slot'],
            "blockNumber":hex(trx['result']['slot']),
            "from":'0x'+sender,
            "gas":'0x%x' % trx['result']['meta']['fee'],
            "gasPrice":'0x00',
            "hash":trxId,
            "input":"0x"+data.hex(),
            "nonce":hex(nonce),
            "to":'0x'+data[17:37].hex(),
            "transactionIndex":hex(0),
            "value":'0x00',
            "v":hex(self.vrs[trxId][0]),
            "r":hex(self.vrs[trxId][1]),
            "s":hex(self.vrs[trxId][2])
        }
        logger.debug ("eth_getTransactionByHash: %s", ret)
        return ret

    def eth_getCode(self, param,  param1):
        return "0x01"

    def eth_sendTransaction(self, trx):
        logger.debug("eth_sendTransaction")
        logger.debug("eth_sendTransaction: type(trx):%s", type(trx))
        logger.debug("eth_sendTransaction: str(trx):%s", str(trx))
        logger.debug("eth_sendTransaction: trx=%s", json.dumps(trx, cls=JsonEncoder, indent=3))
        raise Exception("eth_sendTransaction is not supported. please use eth_sendRawTransaction")

    def eth_sendRawTransaction(self, rawTrx):
        logger.debug('eth_sendRawTransaction rawTrx=%s', rawTrx)
        trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        logger.debug("%s", json.dumps(trx.as_dict(), cls=JsonEncoder, indent=3))

        sender = trx.sender()
        logger.debug('Eth Sender: %s', sender)
        logger.debug('Eth Signature: %s', trx.signature().hex())

        try:
            contract_eth = None
            if (not trx.toAddress):
                (signature, contract_eth) = deploy_contract(self.signer, self.client, trx, self.perm_accs, steps=250)
                #self.contract_address[eth_signature] = contract_eth
            else:
                signature = call_signed(self.signer, self.client, trx, self.perm_accs, steps=250)

            eth_signature = '0x' + bytes(Web3.keccak(bytes.fromhex(rawTrx[2:]))).hex()
            logger.debug('Transaction signature: %s %s', signature, eth_signature)
            if contract_eth: self.contract_address[eth_signature] = contract_eth
            self.signatures[eth_signature] = signature
            self.eth_sender[eth_signature] = sender
            self.vrs[eth_signature] = [trx.v, trx.r, trx.s]

            if (trx.toAddress):
                self.eth_getTransactionReceipt(eth_signature)

            return eth_signature

        except solana.rpc.api.SendTransactionError as err:
            logger.debug("eth_sendRawTransaction solana.rpc.api.SendTransactionError:%s", err.result)
            raise
        except EthereumError as err:
            logger.debug("eth_sendRawTransaction EthereumError:%s", err)
            raise
        except Exception as err:
            logger.debug("eth_sendRawTransaction type(err):%s, Exception:%s", type(err), err)
            raise

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


class SolanaContractTests(unittest.TestCase):
    def setUp(self):
        self.model = EthereumModel()
        self.owner = '0xc1566af4699928fdf9be097ca3dc47ece39f8f8e'
        self.token1 = '0x49a449cd7fd8fbcf34d103d98f2c05245020e35b'
#        self.assertEqual(self.getBalance(self.owner), 1000*10**18)
#        self.assertEqual(self.getBalance(self.token1), 0)

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
        logger.debug('ReceiptId:', receiptId)

        self.assertEqual(self.getBalance(sender), senderBalance - amount)
        self.assertEqual(self.getBalance(receiver), receiverBalance + amount)
        self.assertEqual(self.getBlockNumber(), blockNumber+1)

        receipt = self.model.eth_getTransactionReceipt(receiptId)
        logger.debug('Receipt:', receipt)

        block = self.model.eth_getBlockByNumber(receipt['blockNumber'], False)
        logger.debug('Block:', block)

        self.assertTrue(receiptId in block['transactions'])

    def test_transferTokens(self):
        (token, sender, receiver, amount) = ('0xcf73021fde8654e64421f67372a47aa53c4341a8', '0x324726ca9954ed9bd567a62ae38a7dd7b4eaad0e', '0xb937ad32debafa742907d83cb9749443160de0c4', 32)
        senderBalance = self.getTokenBalance(token, sender)
        receiverBalance = self.getTokenBalance(token, receiver)
        blockNumber = self.getBlockNumber()


        receiptId = self.model.eth_sendRawTransaction('0xf8b018850bdfd63e00830186a094b80102fd2d3d1be86823dd36f9c783ad0ee7d89880b844a9059cbb000000000000000000000000cac68f98c1893531df666f2d58243b27dd351a8800000000000000000000000000000000000000000000000000000000000000208602e92be91e86a05ed7d0093a991563153f59c785e989a466e5e83bddebd9c710362f5ee23f7dbaa023a641d304039f349546089bc0cb2a5b35e45619fd97661bd151183cb47f1a0a')
        logger.debug('ReceiptId:', receiptId)

        self.assertEqual(self.getTokenBalance(token, sender), senderBalance - amount)
        self.assertEqual(self.getTokenBalance(token, receiver), receiverBalance + amount)

        receipt = self.model.eth_getTransactionReceipt(receiptId)
        logger.debug('Receipt:', receipt)

        block = self.model.eth_getBlockByNumber(receipt['blockNumber'], False)
        logger.debug('Block:', block)

        self.assertTrue(receiptId in block['transactions'])



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
            method = getattr(self.model, request['method'])
            response['result'] = method(*request['params'])
        except solana.rpc.api.SendTransactionError as err:
            traceback.print_exc()
            response['error'] = err.result
        except EthereumError as err:
            traceback.print_exc()
            response['error'] = err.getError()
        except Exception as err:
            traceback.print_exc()
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

        # print('headers', request.headers)
        logger.debug('<<< %s 0x%x %s', threading.get_ident(), id(self.model), request.body.decode('utf8'))
        response = None

        try:
            request = json.loads(request.body)
            print('type(request) = ', type(request), request)
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

        logger.debug('>>> %s 0x%0x %s', threading.get_ident(), id(self.model), json.dumps(response))

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

