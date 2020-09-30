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


b'{"id":1,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}'
b'{"id":1,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}'
b'{"id":2073461937540006,"jsonrpc":"2.0","method":"eth_getBalance","params":["0xc1566af4699928fdf9be097ca3dc47ece39f8f8e",null]}'
b'{"id":2073461937540007,"jsonrpc":"2.0","method":"eth_getBalance","params":["0xcac68f98c1893531df666f2d58243b27dd351a88",null]}'
b'{"id":2073461937540008,"jsonrpc":"2.0","method":"eth_getBalance","params":["0x2a2415585e36bdc7d4205b7831e1afecc6709011",null]}'
b'{"id":2073461937540009,"jsonrpc":"2.0","method":"eth_getBalance","params":["0xeb529d4f2bb93a6e4b0453d7eb9a558ed75a7ce2",null]}'
b'{"id":1,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}'
b'{"id":2073461937540010,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":[null,false]}'
b'{"id":1,"jsonrpc":"2.0","method":"eth_blockNumber","params":[]}'
b'{"id":2073461937540011,"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":[null,false]}'
#b'{"id":"d6c43f81-7aca-470b-8c90-8a73e1d2eb0f","jsonrpc":"2.0","method":"eth_call","params":[
#    {"to":"0xb80102fd2d3d1be86823dd36f9c783ad0ee7d898",
#     "data":"0x70a08231000000000000000000000000c1566af4699928fdf9be097ca3dc47ece39f8f8e"},
#     "0x1"]}'


class Token:
    def __init__(self, symbol, decimals, owner, quantity):
        self.symbol = symbol
        self.decimals = decimals
        self.accounts = {owner: int(quantity*10**decimals)}

class Account:
    def __init__(self, balance):
        self.balance = balance
        self.trxCount = 0

    def __repr__(self):
        return str(self.__dict__)

class Solana:
    def __init__(self):
        owner = '0xc1566af4699928fdf9be097ca3dc47ece39f8f8e'
        self.tokens = {
            '0x49a449cd7fd8fbcf34d103d98f2c05245020e35b': Token('GLS', 6, owner, 1000000),
            '0x6dc13a3a38992ca6ee5c9b7562fe17701797cf3d': Token('CYBER', 4, owner, 1000000),
            '0xb80102fd2d3d1be86823dd36f9c783ad0ee7d898': Token('KIA', 3, owner, 100000),
        }
        print(self.tokens)
        self.balances = {owner: Account(1000*10**18)}

    def __repr__(self):
        return str(self.__dict__)

solana = Solana()

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)

class Trx:
    def __init__(self, trxId, sender, receiver):
        self.block = None
        self.index = None
        self.id = trxId
        self.sender = sender
        self.receiver = receiver

    def initBlock(self, block, index):
        if self.block: raise Exception("Transaction already included in block {}".format(block.number))
        (self.block, self.index) = (block, index)

class Block:
    def __init__(self, number):
        self.number = number
        self.trxs = []

    def addTrx(self, trx):
        trx.initBlock(self, len(self.trxs))
        self.trxs.append(trx)


class SolanaContract:
    def __init__(self, solana = solana):
        self.receipts = {}
        self.solana = solana
        self.blocks = [Block(1)]
        self.pending = Block(len(self.blocks)+1)
        self.trxs = {}
        pass

    def net_version(self):
        return '1600243666737'

    def commitBlock(self):
        self.blocks.append(self.pending)
        self.pending = Block(len(self.blocks)+1)

    def addTrx(self, trx):
        self.pending.addTrx(trx)
        self.trxs[trx.id] = trx

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
        balance = self.solana.balances[account].balance if account in self.solana.balances else 0
        print('GetBalance for {} equal {}'.format(account, balance))
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
            "transactions": [trx.id for trx in block.trxs],
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
        functions = {
            '0x06fdde03': 'name',
            '0x313ce567': 'decimals',
            '0x95d89b41': 'symbol',
            '0x18160ddd': 'totalSupply',
            '0x70a08231': 'balanceOf',
        }
        if obj['data'] is None: raise Exception("Missing data")
        funcName = functions.get(obj['data'][0:10], None)
        if funcName is None: raise Exception("Unknown function")
        func = getattr(self, 'token_'+funcName)
        return func(obj['to'], obj['data'][10:])

    def eth_getTransactionCount(self, account, tag):
        if account in self.solana.balances:
            return hex(self.solana.balances[account].trxCount)
        else:
            return '0x0'

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

    def eth_sendRawTransaction(self, rawTrx):
        trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        (sender, toAddress) = ('0x'+trx.sender(), '0x'+trx.toAddress.hex())
        print(json.dumps(trx.__dict__, cls=JsonEncoder, indent=3))
        print('Sender:', sender, 'toAddress', toAddress)
        if not sender in self.solana.balances: self.solana.balances[sender] = Account(0)
        senderAccount = self.solana.balances[sender]
#        if senderAccount.trxCount != trx.nonce:
#            raise Exception("Incorrect nonce: current {}, received {}".format(senderAccount.trxCount, trx.nonce))

        if trx.value:
            if senderAccount.balance < trx.value:
                raise Exception("Unsufficient funds")
            if not toAddress in self.solana.balances: self.solana.balances[toAddress] = Account(0)
            receiverAccount = self.solana.balances[toAddress]

            senderAccount.balance -= trx.value
            receiverAccount.balance += trx.value
        try:
            if trx.callData:
                functions = {
                    'a9059cbb': 'transfer',
                }
                data = trx.callData.hex()
                funcName = functions.get(data[0:8], None)
                print('funcName:', funcName, 'callData:', data[0:8])
                if funcName is None: raise Exception("Unknown function")
                func = getattr(self, 'token_'+funcName)
                func(sender, toAddress, data[8:])
        except:
            if trx.value:
                senderAccount.balance += trx.value
                receiverAccount.balance -= trx.value
            raise

        receipt = '0x%064x' % len(self.trxs)      # !!!!! Strong 64-symbol length !!!!!
        self.addTrx(Trx(receipt, sender, toAddress))
        self.commitBlock()
        return receipt
#        print('Receipt:', receipt)
#        self.receipts[receipt] = {
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
#        }
#        self.blockNumber += 1
#        print('Self:', self)
#        return receipt
#{
#    "id":1443458528322211,
#    "jsonrpc":"2.0",
#    "result":{
#        "number":"0x18",
#        "hash":"0xda2ebd8e23581390844cbaffeec6863759434f4ad9c273517ab31ccd2ec82f3a",
#        "parentHash":"0x439dc6b874b18654401eb702684a1a3809f6b5e7f1ad9608b7528e2ff58c21a5",
#        "mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
#        "nonce":"0x0000000000000000",
#        "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
#        "logsBloom":"0x"+'0'*512,
#        "transactionsRoot":"0x28bdd619dfade4f0bc6f1f190d9b7522db781cd0813de9465a9b0e32f505383f",
#        "stateRoot":"0x1a2f954dbc180f55c0c41ea656a1dd88af1fd6e96fdb38d1b7d46221e4339466",
#        "receiptsRoot":"0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
#        "miner":"0x0000000000000000000000000000000000000000",
#        "difficulty":"0x0",
#        "totalDifficulty":"0x0",
#        "extraData":"0x",
#        "size":"0x3e8",
#        "gasLimit":"0x6691b7",
#        "gasUsed":"0x5208",
#        "timestamp":"0x5f72ceee",
#        "transactions":[
#            "0xaf4f2ad96f8e8c1bf8105e81fd050435173d7141e7703f347604fe3b1b899268"
#        ],
#        "uncles":[]
#    }
#} 

    def token_balanceOf(self, to, data):
        account = '0x'+data[24:]
        token = to
        print("Get {} balance in {} token".format(account, token))
        if token in self.solana.tokens and account in self.solana.tokens[token].accounts:
            return '%064x' % self.solana.tokens[token].accounts[account]
        return "0x0"

    def token_decimals(self, to, data):
        print("Get symbol for {}".format(to))
        token = self.solana.tokens.get(to, None)
        if not token: return '0x'
        else: return '%064x'%token.decimals

    def token_symbol(self, to, data):
        print("Get decimals for {}".format(to))
        token = self.solana.tokens.get(to, None)
        if not token: return '0x'
        symbol = token.symbol
        result = '%064x%064x%s'%(0x20, len(symbol), symbol.encode('utf8').hex())
        result += (64-len(result)%64)%64 * '0'
        return result
        
    def token_transfer(self, to, sender, data):
        receiver = int(data[0:64], 16)
        amount = int(data[64:128], 16)
        print('Transfer {} --{}--> {}'.format(sender, amount, receiver))
        if not to in self.solana.tokens:
            raise Exception("Unknown token contract")
        token = self.solana.tokents[to]
        if not (sender in token.accounts and token.accounts[sender] >= amount):
            raise Exception("Unsufficient funds")

        token.accounts[sender] -= amount

        if not receiver in token.accounts:
            token.accounts[receiver] = amount
        else:
            token.accounts[receiver] += amount



class SolanaContractTests(unittest.TestCase):
    def setUp(self):
        self.solana = Solana()
        self.contract = SolanaContract(self.solana)
        self.owner = '0xc1566af4699928fdf9be097ca3dc47ece39f8f8e'
        self.token1 = '0x49a449cd7fd8fbcf34d103d98f2c05245020e35b'
        self.assertEqual(self.getBalance(self.owner), 1000*10**18)
        self.assertEqual(self.getBalance(self.token1), 0)

    def getBalance(self, account):
        return int(self.contract.eth_getBalance(account, 'latest'), 16)

    def getBlockNumber(self):
        return int(self.contract.eth_blockNumber(), 16)

    def test_transferFunds(self):
        (sender, receiver, amount) = (self.owner, '0x8d900bfa2353548a4631be870f99939575551b60', 123*10**18)
        senderBalance = self.getBalance(sender)
        receiverBalance = self.getBalance(receiver)
        blockNumber = self.getBlockNumber()

        receiptId = self.contract.eth_sendRawTransaction('0xf8730a85174876e800825208948d900bfa2353548a4631be870f99939575551b608906aaf7c8516d0c0000808602e92be91e86a040a2a5d73931f66185e8526f09c4d0dc1f389c1b9fcd5e37a012839e6c5c70f0a00554615806c3fa7dc7c8096b3bfed5a29354045e56982bdf3ee11f649e53d51e')
        print('Self.solana', self.solana)
        print('Solana', solana)
        print('ReceiptId:', receiptId)
        
        self.assertEqual(self.getBalance(sender), senderBalance - amount)
        self.assertEqual(self.getBalance(receiver), receiverBalance + amount)
        self.assertEqual(self.getBlockNumber(), blockNumber+1)

        receipt = self.contract.eth_getTransactionReceipt(receiptId)
        print('Receipt:', receipt)

        block = self.contract.eth_getBlockByNumber(receipt['blockNumber'], False)
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
        self.contract = SolanaProxyPlugin.getContract()

    @classmethod
    def getContract(cls):
        if not hasattr(cls, 'contractInstance'):
            cls.contractInstance = SolanaContract()
        return cls.contractInstance

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
            method = getattr(self.contract, req['method'])
            res['result'] = method(*req['params'])
        except Exception as err:
            res['error'] = {'code': -32000, 'message': str(err)}
            with socket_connection(('localhost', 8545)) as conn:
                conn.send(request.build())
                orig = HttpParser.response(memoryview(conn.recv(DEFAULT_BUFFER_SIZE)))
                print('- ', orig.body.decode('utf8'))
        
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

