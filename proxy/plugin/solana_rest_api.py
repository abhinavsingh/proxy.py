# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import random
from datetime import datetime
from typing import List, Tuple
from urllib import parse as urlparse
import json
import unittest

from ..common.constants import DEFAULT_BUFFER_SIZE, DEFAULT_HTTP_PORT
from ..common.utils import socket_connection, text_, build_http_response
from ..http.codes import httpStatusCodes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes

from .eth_proto import Trx as EthTrx


class Contract:
    def __init__(self, functions):
        self.functions = functions

    def _getFunction(self, prefix, funcHash):
        funcName = self.functions.get(funcHash, None)
        if not funcName: raise Exception("Unknown function")
        return getattr(self, prefix+funcName)

    def call(self, data):
        return self._getFunction('call_', data[0:8])(data[8:])

    def execute(self, sender, data):
        self._getFunction('execute_', data[0:8])(sender, data[8:])

class TokenContract(Contract):
    def __init__(self, symbol, decimals, owner, quantity):
        functions = {
            '06fdde03': 'name',
            '313ce567': 'decimals',
            '95d89b41': 'symbol',
            '18160ddd': 'totalSupply',
            '70a08231': 'balanceOf',
            'a9059cbb': 'transfer',
        }
        super(TokenContract, self).__init__(functions)
        self.symbol = symbol
        self.decimals = decimals
        self.balances = {owner: int(quantity*10**decimals)}

    def call_balanceOf(self, data):
        balance = self.balances.get('0x'+data[24:], None)
        return '%064x' % balance if balance else '0x0'

    def call_decimals(self, data):
        return '%064x' % self.decimals

    def call_symbol(self, data):
        result = '%064x%064x%s'%(0x20, len(self.symbol), self.symbol.encode('utf8').hex())
        result += (64-len(result)%64)%64 * '0'
        return result

    def execute_transfer(self, sender, data):
        receiver = '0x'+data[24:64]
        amount = int(data[64:128], 16)
        if not (sender in self.balances and self.balances[sender] >= amount):
            raise Exception("Unsufficient funds")

        self.balances[sender] -= amount
        if not receiver in self.balances:
            self.balances[receiver] = amount
        else:
            self.balances[receiver] += amount


class Account:
    def __init__(self, balance):
        self.balance = balance
        self.trxCount = 1

    def __repr__(self):
        return str(self.__dict__)

class Receipt:
    def __init__(self, receiptId, sender, receiver):
        self.block = None
        self.index = None
        self.id = receiptId
        self.sender = sender
        self.receiver = receiver

    def initBlock(self, block, index):
        if self.block: raise Exception("Transaction already included in block {}".format(block.number))
        (self.block, self.index) = (block, index)

class Block:
    def __init__(self, number):
        self.number = number
        self.receipts = []

    def addReceipt(self, receipt):
        receipt.initBlock(self, len(self.receipts))
        self.receipts.append(receipt)


class EthereumModel:
    def __init__(self):
        self.receipts = {}
        self.blocks = [Block(1)]
        self.pending = Block(len(self.blocks)+1)
        self.trxs = {}

        owner = '0xc1566af4699928fdf9be097ca3dc47ece39f8f8e'
        self.contracts = {
            '0x59a449cd7fd8fbcf34d103d98f2c05245020e35b': TokenContract('GLS', 6, owner, 1000000),
            '0x7dc13a3a38992ca6ee5c9b7562fe17701797cf3d': TokenContract('CYBER', 4, owner, 1000000),
            '0xc80102fd2d3d1be86823dd36f9c783ad0ee7d898': TokenContract('KIA', 3, owner, 100000),
        }
        print(self.contracts)
        self.accounts = {owner: Account(1000*10**18)}
        pass

    def _getContract(self, contractId):
        contract = self.contracts.get(contractId)
        if not contract: raise Exception("Unknown contract {}".format(contractId))
        return contract

    def net_version(self):
        return '1600243666737'

    def commitBlock(self):
        self.blocks.append(self.pending)
        self.pending = Block(len(self.blocks)+1)

    def addReceipt(self, receipt):
        self.pending.addReceipt(receipt)
        self.trxs[receipt.id] = receipt

    def __repr__(self):
        return str(self.__dict__)

    def eth_blockNumber(self):
        print("eth_blockNumber", self)
        return hex(len(self.blocks))

    def eth_getBalance(self, account, tag):
        """account - address to check for balance.
           tag - integer block number, or the string "latest", "earliest" or "pending"
        """
        account = account.lower()
        account = self.accounts.get(account.lower())
        balance = account.balance if account else 0
        return hex(balance)

    def eth_getBlockByNumber(self, tag, full):
        """Returns information about a block by block number.
            tag - integer of a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        if tag in ('earliest', 'latest', 'pending'): raise Exception("Invalid tag {}".format(tag))
        number = int(tag, 16)
        if len(self.blocks) > number: raise Exception("Invalid block number {}. Maximum: {}".format(tag, len(self.blocks)))
        block = self.blocks[number-1]
        return {
            "number": block.number,
            "gasLimit": "0x6691b7",
            "transactions": [receipt.id for receipt in block.receipts],
        }
#       {
#            "number":tag,
#            "hash":"0x40baaba3f7cd6397ebdfe105a778854418112f6218969ae0600907936dea7077",
#            "parentHash":"0x312f4c211e84a7f8cd53e7ecb90ad194e58bcea15dfdfed4314412a5d7f4c8bf",
#            "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
#            "nonce":"0x0000000000000000",
#            "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
#            "logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
#            "transactionsRoot":"0x0f1662bc2d4cca30a1e039d72b4fc39fe2fbb32f4d79e4ec21add97c446a3352",
#            "stateRoot":"0x9714bb6d61f0c6095cb14f526a98e546e6dd35d8ac60e11682fc5f984c7ce761",
#            "receiptsRoot":"0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
#            "miner":"0x0000000000000000000000000000000000000000",
#            "difficulty":"0x0",
#            "totalDifficulty":"0x0",
#            "extraData":"0x",
#            "size":"0x3e8",
#            "gasLimit":"0x6691b7",
#            "gasUsed":"0x5208",
#            "timestamp":"0x5f61ea48",
#            "transactions":[
#                "0x7fe4d5e32ad2099940654c7871079a7dcdf84b592823ad6a2f7835a55453fae1"
#            ],
#            "uncles":[]
#        }

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
        return self._getContract(obj['to']).call(obj['data'][2:])

    def eth_getTransactionCount(self, account, tag):
        account = self.accounts.get(account)
        return hex(account.trxCount if account else 0)

    def eth_getTransactionReceipt(self, trxId):
        receipt = self.trxs.get(trxId, None)
        if not receipt: raise Exception("Not found receipt")
        return {
            "transactionHash":receipt.id,
            "transactionIndex":hex(receipt.index),
            "blockHash":receipt.id,
            "blockNumber":hex(receipt.block.number),
            "from":receipt.sender,
            "to":receipt.receiver,
            "gasUsed":"0x5208",
            "cumulativeGasUsed":"0x5208",
            "contractAddress":None,
            "logs":[],
            "status":"0x1",
            "logsBloom":"0x"+'0'*512
        }
#            "transactionHash":receipt,
#            "transactionIndex":"0x0",
#            "blockHash":receipt,
#            "blockNumber":"0x%x" % self.blockNumber,
#            "from":sender,
#            "to":toAddress,
#            "gasUsed":"0x5208",
#            "cumulativeGasUsed":"0x5208",
#            "contractAddress":None,
#            "logs":[],
#            "status":"0x1",
#            "logsBloom":"0x"+'0'*512

    def eth_sendRawTransaction(self, rawTrx):
        trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        (sender, toAddress) = ('0x'+trx.sender(), '0x'+trx.toAddress.hex())
        print(json.dumps(trx.__dict__, cls=JsonEncoder, indent=3))
        print('Sender:', sender, 'toAddress', toAddress)
        if not sender in self.accounts: self.accounts[sender] = Account(0)
        senderAccount = self.accounts[sender]
        if senderAccount.trxCount != trx.nonce:
            raise Exception("Incorrect nonce: current {}, received {}".format(senderAccount.trxCount, trx.nonce))
            pass

        if trx.value:
            if senderAccount.balance < trx.value:
                raise Exception("Unsufficient funds")
            if not toAddress in self.accounts: self.accounts[toAddress] = Account(0)
            receiverAccount = self.accounts[toAddress]

            senderAccount.balance -= trx.value
            receiverAccount.balance += trx.value
        try:
            if trx.callData:
                self._getContract(toAddress).execute(sender, trx.callData.hex())
        except:
            if trx.value:
                senderAccount.balance += trx.value
                receiverAccount.balance -= trx.value
            raise

        receiptHash = '0x%064x' % len(self.trxs)      # !!!!! Strong 64-symbol length !!!!!
        self.addReceipt(Receipt(receiptHash, sender, toAddress))
        self.commitBlock()
        return receiptHash


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


class SolanaContractTests(unittest.TestCase):
    def setUp(self):
        self.model = EthereumModel()
        self.owner = '0xc1566af4699928fdf9be097ca3dc47ece39f8f8e'
        self.token1 = '0x49a449cd7fd8fbcf34d103d98f2c05245020e35b'
        self.assertEqual(self.getBalance(self.owner), 1000*10**18)
        self.assertEqual(self.getBalance(self.token1), 0)

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
        print('ReceiptId:', receiptId)
        
        self.assertEqual(self.getBalance(sender), senderBalance - amount)
        self.assertEqual(self.getBalance(receiver), receiverBalance + amount)
        self.assertEqual(self.getBlockNumber(), blockNumber+1)

        receipt = self.model.eth_getTransactionReceipt(receiptId)
        print('Receipt:', receipt)

        block = self.model.eth_getBlockByNumber(receipt['blockNumber'], False)
        print('Block:', block)

        self.assertTrue(receiptId in block['transactions'])

    def test_transferTokens(self):
        (token, sender, receiver, amount) = ('0xb80102fd2d3d1be86823dd36f9c783ad0ee7d898', self.owner, '0xcac68f98c1893531df666f2d58243b27dd351a88', 32)
        senderBalance = self.getTokenBalance(token, sender)
        receiverBalance = self.getTokenBalance(token, receiver)
        blockNumber = self.getBlockNumber()

        receiptId = self.model.eth_sendRawTransaction('0xf8b018850bdfd63e00830186a094b80102fd2d3d1be86823dd36f9c783ad0ee7d89880b844a9059cbb000000000000000000000000cac68f98c1893531df666f2d58243b27dd351a8800000000000000000000000000000000000000000000000000000000000000208602e92be91e86a05ed7d0093a991563153f59c785e989a466e5e83bddebd9c710362f5ee23f7dbaa023a641d304039f349546089bc0cb2a5b35e45619fd97661bd151183cb47f1a0a')
        print('ReceiptId:', receiptId)

        self.assertEqual(self.getTokenBalance(token, sender), senderBalance - amount)
        self.assertEqual(self.getTokenBalance(token, receiver), receiverBalance + amount)

        receipt = self.model.eth_getTransactionReceipt(receiptId)
        print('Receipt:', receipt)
        
        block = self.model.eth_getBlockByNumber(receipt['blockNumber'], False)
        print('Block:', block)

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
        if not hasattr(cls, 'modelInstance'):
            cls.modelInstance = EthereumModel()
        return cls.modelInstance

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, SolanaProxyPlugin.SOLANA_PROXY_LOCATION),
            (httpProtocolTypes.HTTPS, SolanaProxyPlugin.SOLANA_PROXY_LOCATION)
        ]

    def handle_request(self, request: HttpParser) -> None:
        print('< ', request.body.decode('utf8'))
        req = json.loads(request.body)
        res = {'id':req['id'], 'jsonrpc':'2.0'}

        try:
            method = getattr(self.model, req['method'])
            res['result'] = method(*req['params'])
        except Exception as err:
            res['error'] = {'code': -32000, 'message': str(err)}
#            with socket_connection(('localhost', 8545)) as conn:
#                conn.send(request.build())
#                orig = HttpParser.response(memoryview(conn.recv(DEFAULT_BUFFER_SIZE)))
#                print('- ', orig.body.decode('utf8'))
        
        print('> ', json.dumps(res))

        self.client.queue(memoryview(build_http_response(
            httpStatusCodes.OK, body=json.dumps(res).encode('utf8'),
            headers={b'Content-Type': b'application/json'})))

    def on_websocket_open(self) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def on_websocket_close(self) -> None:
        pass

