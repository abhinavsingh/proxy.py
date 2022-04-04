# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import threading
import traceback
import time
import hashlib
import multiprocessing
import sha3

from logged_groups import logged_group, logging_context
from typing import Optional, Union

from ..common.utils import build_http_response
from ..http.codes import httpStatusCodes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from typing import List, Tuple

from ..common_neon.transaction_sender import NeonTxSender
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_receipt_parser import SolTxError
from ..common_neon.address import EthereumAddress
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.errors import EthereumError, PendingTxError
from ..common_neon.estimate import GasEstimate
from ..common_neon.utils import SolanaBlockInfo
from ..common_neon.keys_storage import KeyStorage
from ..environment import SOLANA_URL, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, EVM_STEP_COUNT, CHAIN_ID, ENABLE_PRIVATE_API
from ..environment import NEON_EVM_VERSION, NEON_EVM_REVISION
from ..environment import neon_cli
from ..memdb.memdb import MemDB
from .gas_price_calculator import GasPriceCalculator
from ..common_neon.eth_proto import Trx as EthTrx
from web3.auto import w3

modelInstanceLock = threading.Lock()
modelInstance = None

NEON_PROXY_PKG_VERSION = '0.7.7-dev'
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

    @staticmethod
    def neon_proxy_version():
        return 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION

    @staticmethod
    def web3_clientVersion():
        return 'Neon/v' + NEON_EVM_VERSION + '-' + NEON_EVM_REVISION

    @staticmethod
    def eth_chainId():
        return hex(int(CHAIN_ID))

    @staticmethod
    def neon_cli_version():
        return neon_cli().version()

    @staticmethod
    def net_version():
        return str(CHAIN_ID)

    def eth_gasPrice(self):
        return hex(int(self.gas_price_calculator.get_suggested_gas_price()))

    def eth_estimateGas(self, param):
        try:
            calculator = GasEstimate(param, self._solana)
            calculator.execute()
            return hex(calculator.estimate())

        except EthereumError:
            raise
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Exception on eth_estimateGas: {err}: {err_tb}")
            raise

    def __repr__(self):
        return str(self.__dict__)

    def _process_block_tag(self, tag) -> SolanaBlockInfo:
        if tag in ("latest", "pending"):
            block = self._db.get_latest_block()
        elif tag in ('earliest'):
            raise EthereumError(message=f"invalid tag {tag}")
        elif isinstance(tag, str):
            try:
                block = SolanaBlockInfo(slot=int(tag.strip(), 16))
            except:
                raise EthereumError(message=f'failed to parse block tag: {tag}')
        elif isinstance(tag, int):
            block = SolanaBlockInfo(slot=tag)
        else:
            raise EthereumError(message=f'failed to parse block tag: {tag}')
        return block

    @staticmethod
    def _validate_tx_id(tag: str) -> Optional[str]:
        try:
            if not isinstance(tag, str):
                return 'bad transaction-id format'
            tag = tag.lower().strip()
            assert len(tag) == 66
            assert tag[:2] == '0x'

            int(tag[2:], 16)
            return None
        except:
            return 'transaction-id is not hex'

    def _get_full_block_by_number(self, tag) -> SolanaBlockInfo:
        block = self._process_block_tag(tag)
        if block.slot is None:
            self.debug(f"Not found block by number {tag}")
            return block

        if block.is_empty():
            block = self._db.get_full_block_by_slot(block.slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.slot}")

        return block

    def eth_blockNumber(self):
        slot = self._db.get_latest_block_slot()
        return hex(slot)

    def eth_getBalance(self, account, tag) -> str:
        """account - address to check for balance.
           tag - integer block number, or the string "latest", "earliest" or "pending"
        """
        if tag not in ("latest", "pending"):
            self.debug(f"Block type '{tag}' is not supported yet")
            raise EthereumError(message=f"Not supported block identifier: {tag}")

        self.debug(f'eth_getBalance: {account}')
        try:
            neon_account_info = self._solana.get_neon_account_info(EthereumAddress(account))
            if neon_account_info is None:
                return hex(0)

            return hex(neon_account_info.balance)
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
            from_block = self._process_block_tag(obj['fromBlock']).slot
        if 'toBlock' in obj and obj['toBlock'] not in ('latest', 'pending'):
            to_block = self._process_block_tag(obj['toBlock']).slot
        if 'address' in obj:
            addresses = to_list(obj['address'])
        if 'topics' in obj:
            topics = to_list(obj['topics'])
        if 'blockHash' in obj:
            block_hash = obj['blockHash']

        return self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def _get_block_by_slot(self, block: SolanaBlockInfo, full, skip_transaction) -> Optional[dict]:
        if block.is_empty():
            block = self._db.get_full_block_by_slot(block.slot)
            if block.is_empty():
                return None

        sign_list = []
        gas_used = 0
        if skip_transaction:
            tx_list = []
        else:
            tx_list = self._db.get_tx_list_by_sol_sign(block.is_finalized, block.signs)

        for tx in tx_list:
            gas_used += int(tx.neon_res.gas_used, 16)

            if full:
                receipt = self._get_transaction(tx)
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
        if block_identifier not in ("latest", "pending"):
            self.debug(f"Block type '{block_identifier}' is not supported yet")
            raise EthereumError(message=f"Not supported block identifier: {block_identifier}")

        try:
            value = neon_cli().call('get-storage-at', account, position)
            return value
        except Exception as err:
            self.error(f"eth_getStorageAt: Neon-cli failed to execute: {err}")
            return '0x00'

    def _get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        try:
            block_hash = block_hash.strip().lower()
            assert block_hash[:2] == '0x'

            bin_block_hash = bytes.fromhex(block_hash[2:])
            assert len(bin_block_hash) == 32
        except:
            raise EthereumError(message=f'bad block hash {block_hash}')

        block = self._db.get_block_by_hash(block_hash)
        if block.slot is None:
            self.debug("Not found block by hash %s", block_hash)

        return block

    def eth_getBlockByHash(self, block_hash: str, full: bool) -> Optional[dict]:
        """Returns information about a block by hash.
            block_hash - Hash of a block.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block = self._get_block_by_hash(block_hash)
        if block.slot is None:
            return None
        ret = self._get_block_by_slot(block, full, False)
        return ret

    def eth_getBlockByNumber(self, tag, full) -> Optional[dict]:
        """Returns information about a block by block number.
            tag - integer of a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block = self._process_block_tag(tag)
        if block.slot is None:
            self.debug(f"Not found block by number {tag}")
            return None
        ret = self._get_block_by_slot(block, full, tag in ('latest', 'pending'))
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
        if tag not in ("latest", "pending"):
            self.debug(f"Block type '{tag}' is not supported yet")
            raise EthereumError(message=f"Not supported block identifier: {tag}")

        if not obj['data']: raise EthereumError(message="Missing data")
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
        if tag not in ("latest", "pending"):
            self.debug(f"Block type '{tag}' is not supported yet")
            raise EthereumError(message=f"Not supported block identifier: {tag}")

        try:
            neon_account_info = self._solana.get_neon_account_info(EthereumAddress(account))
            return hex(neon_account_info.trx_count)
        except Exception as err:
            self.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    @staticmethod
    def _get_transaction_receipt(tx) -> dict:
        result = {
            "transactionHash": tx.neon_tx.sign,
            "transactionIndex": hex(tx.neon_tx.tx_idx),
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

    def eth_getTransactionReceipt(self, NeonTxId: str) -> Optional[dict]:
        error = self._validate_tx_id(NeonTxId)
        if error:
            raise EthereumError(message=error)
        neon_sign = NeonTxId.strip().lower()

        tx = self._db.get_tx_by_neon_sign(neon_sign)
        if not tx:
            self.debug("Not found receipt")
            return None
        return self._get_transaction_receipt(tx)

    @staticmethod
    def _get_transaction(tx) -> dict:
        t = tx.neon_tx
        r = tx.neon_res

        result = {
            "blockHash": r.block_hash,
            "blockNumber": hex(r.slot),
            "hash": t.sign,
            "transactionIndex": hex(t.tx_idx),
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

    def eth_getTransactionByHash(self, NeontxId: str) -> Optional[dict]:
        error = self._validate_tx_id(NeontxId)
        if error:
            raise EthereumError(message=error)

        neon_sign = NeontxId.strip().lower()
        tx = self._db.get_tx_by_neon_sign(neon_sign)
        if tx is None:
            self.debug("Not found receipt")
            return None
        return self._get_transaction(tx)

    def eth_getCode(self, account, _tag):
        account = account.lower()
        return self._db.get_contract_code(account)

    def eth_sendRawTransaction(self, rawTrx):
        trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        self.debug(f"{json.dumps(trx.as_dict(), cls=JsonEncoder, sort_keys=True)}")
        min_gas_price = self.gas_price_calculator.get_min_gas_price()

        if trx.gasPrice < min_gas_price:
            raise EthereumError(message="The transaction gasPrice is less than the minimum allowable value" +
                                f"({trx.gasPrice}<{min_gas_price})")

        eth_signature = '0x' + trx.hash_signed().hex()

        try:
            tx_sender = NeonTxSender(self._db, self._solana, trx, steps=EVM_STEP_COUNT)
            tx_sender.execute()
            return eth_signature

        except PendingTxError as err:
            self.debug(f'{err}')
            return eth_signature
        except EthereumError as err:
            # self.debug(f"eth_sendRawTransaction EthereumError: {err}")
            raise
        except Exception as err:
            # self.error(f"eth_sendRawTransaction type(err): {type(err}}, Exception: {err}")
            raise

    def _get_transaction_by_index(self, block: SolanaBlockInfo, tx_idx: int) -> Optional[dict]:
        try:
            if isinstance(tx_idx, str):
                tx_idx = int(tx_idx, 16)
            assert tx_idx >= 0
        except:
            raise EthereumError(message=f'invalid transaction index {tx_idx}')

        if block.is_empty():
            block = self._db.get_full_block_by_slot(block.slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.slot}")
                return None

        tx_list = self._db.get_tx_list_by_sol_sign(block.is_finalized, block.signs)
        if tx_idx >= len(tx_list):
            return None

        return self._get_transaction(tx_list[tx_idx])

    def eth_getTransactionByBlockNumberAndIndex(self, tag: str, tx_idx: int) -> Optional[dict]:
        block = self._process_block_tag(tag)
        if block.is_empty():
            self.debug(f"Not found block by number {tag}")
            return None

        return self._get_transaction_by_index(block, tx_idx)

    def eth_getTransactionByBlockHashAndIndex(self, block_hash: str, tx_idx: int) -> Optional[dict]:
        block = self._get_block_by_hash(block_hash)
        if block.is_empty():
            return None
        return self._get_transaction_by_index(block, tx_idx)

    def eth_getBlockTransactionCountByHash(self, block_hash: str) -> str:
        block = self._get_block_by_hash(block_hash)
        if block.slot is None:
            return hex(0)
        if block.is_empty():
            block = self._db.get_full_block_by_slot(block.slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.slot}")
                return hex(0)

        tx_list = self._db.get_tx_list_by_sol_sign(block.is_finalized, block.signs)
        return hex(len(tx_list))

    def eth_getBlockTransactionCountByNumber(self, tag: str) -> str:
        block = self._get_full_block_by_number(tag)
        if block.is_empty():
            return hex(0)

        tx_list = self._db.get_tx_list_by_sol_sign(block.is_finalized, block.signs)
        return hex(len(tx_list))

    @staticmethod
    def eth_accounts() -> [str]:
        storage = KeyStorage()
        account_list = storage.get_list()
        return [str(a) for a in account_list]

    @staticmethod
    def eth_sign(address: str, data: str) -> str:
        try:
            address = address.lower()
            bin_address = bytes.fromhex(address[2:])
            assert len(bin_address) == 20
        except:
            raise EthereumError(message='bad account')

        account = KeyStorage().get_key(address)
        if not account:
            raise EthereumError(message='unknown account')

        try:
            data = bytes.fromhex(data[2:])
        except:
            raise EthereumError(message='data is not hex string')

        message = str.encode(f'\x19Ethereum Signed Message:\n{len(data)}') + data
        return str(account.private.sign_msg(message))

    def eth_signTransaction(self, tx: dict) -> dict:
        try:
            sender = tx['from']
            bin_sender = bytes.fromhex(sender[2:])
            assert len(bin_sender) == 20
        except:
            raise EthereumError(message='bad account')

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        try:
            if 'from' in tx:
                del tx['from']
            if 'to' in tx:
                del tx['to']
            if 'nonce' not in tx:
                tx['nonce'] = self.eth_getTransactionCount(sender, 'latest')
            if 'chainId' not in tx:
                tx['chainId'] = hex(CHAIN_ID)

            signed_tx = w3.eth.account.sign_transaction(tx, account.private)
            raw_tx = signed_tx.rawTransaction.hex()

            tx['from'] = sender
            tx['to'] = EthTrx.fromString(bytearray.fromhex(raw_tx[2:])).toAddress.hex()
            tx['hash'] = signed_tx.hash.hex()
            tx['r'] = hex(signed_tx.r)
            tx['s'] = hex(signed_tx.s)
            tx['v'] = hex(signed_tx.v)

            return {
                'raw': raw_tx,
                'tx': tx
            }
        except:
            raise EthereumError(message='bad transaction')

    def eth_sendTransaction(self, tx):
        tx = self.eth_signTransaction(tx)
        return self.eth_sendRawTransaction(tx['raw'])

    @staticmethod
    def web3_sha3(data: str) -> str:
        try:
            data = bytes.fromhex(data[2:])
        except:
            raise EthereumError(message='data is not hex string')

        return sha3.keccak_256(data).hexdigest()

    @staticmethod
    def eth_mining() -> bool:
        return False

    @staticmethod
    def eth_hashrate() -> str:
        return hex(0)

    @staticmethod
    def eth_getWork() -> [str]:
        return ['', '', '', '']

    def eth_syncing(self) -> Union[bool, dict]:
        try:
            slots_behind = self._solana.get_slots_behind()
            latest_slot = self._db.get_latest_block_slot()
            first_slot = self._db.get_starting_block_slot()

            self.debug(f'slots_behind: {slots_behind}, latest_slot: {latest_slot}, first_slot: {first_slot}')
            if (slots_behind is None) or (latest_slot is None) or (first_slot is None):
                return False

            return {
                'startingblock': first_slot,
                'currentblock': latest_slot,
                'highestblock': latest_slot + slots_behind
            }
        except:
            return False

    def net_peerCount(self) -> str:
        cluster_node_list = self._solana.get_cluster_nodes()
        return hex(len(cluster_node_list))

    @staticmethod
    def net_listening() -> bool:
        return False

    def neon_getSolanaTransactionByNeonTransaction(self, NeonTxId: str) -> Union[str, list]:
        error = self._validate_tx_id(NeonTxId)
        if error:
            raise EthereumError(message=error)
        return self._db.get_sol_sign_list_by_neon_sign(NeonTxId.strip().lower())


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

        def is_private_api(method: str) -> bool:
            if method.startswith('_'):
                return True

            if ENABLE_PRIVATE_API:
                return False

            private_method_map = set([
                "eth_accounts",
                "eth_sign",
                "eth_sendTransaction",
                "eth_signTransaction",
            ])
            return method in private_method_map

        try:
            if (not hasattr(self.model, request['method'])) or is_private_api(request["method"]):
                response['error'] = {'code': -32601, 'message': f'method {request["method"]} is not supported'}
            else:
                method = getattr(self.model, request['method'])
                params = request.get('params', [])
                response['result'] = method(*params)
        except SolTxError as err:
            # traceback.print_exc()
            response['error'] = {'code': -32000, 'message': err.error}
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
