import json
import multiprocessing
import traceback
from typing import Optional, Union

import sha3
from logged_groups import logged_group
from web3.auto import w3

from ..common_neon.address import EthereumAddress
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.errors import EthereumError, InvalidParamError, PendingTxError
from ..common_neon.estimate import GasEstimate
from ..common_neon.eth_proto import Trx as EthTrx
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.utils import SolanaBlockInfo
from ..environment import SOLANA_URL, PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, NEON_EVM_VERSION, NEON_EVM_REVISION, \
                          CHAIN_ID, neon_cli, EVM_STEP_COUNT
from ..memdb.memdb import MemDB
from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..statistics_exporter.proxy_metrics_interface import StatisticsExporter

from .transaction_sender import NeonTxSender

NEON_PROXY_PKG_VERSION = '0.7.16-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


@logged_group("neon.Proxy")
class NeonRpcApiModel:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self):
        self._solana = SolanaInteractor(SOLANA_URL)
        self._db = MemDB(self._solana)
        self._stat_exporter: Optional[StatisticsExporter] = None

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

    def set_stat_exporter(self, stat_exporter: StatisticsExporter):
        self._stat_exporter = stat_exporter

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
        gas_price = self.gas_price_calculator.get_suggested_gas_price()
        return hex(gas_price)

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
        elif tag == 'earliest':
            block = self._db.get_starting_block()
        elif isinstance(tag, str):
            try:
                block = SolanaBlockInfo(slot=int(tag.strip(), 16))
            except (Exception,):
                raise InvalidParamError(message=f'failed to parse block tag: {tag}')
        elif isinstance(tag, int):
            block = SolanaBlockInfo(slot=tag)
        else:
            raise InvalidParamError(message=f'failed to parse block tag: {tag}')
        return block

    @staticmethod
    def _normalize_tx_id(tag: str) -> str:
        if not isinstance(tag, str):
            raise InvalidParamError(message='bad transaction-id format')

        try:
            tag = tag.lower().strip()
            assert len(tag) == 66
            assert tag[:2] == '0x'

            int(tag[2:], 16)
            return tag
        except (Exception,):
            raise InvalidParamError(message='transaction-id is not hex')

    @staticmethod
    def _validate_block_tag(tag: str):
        # if tag not in ("latest", "pending"):
        #     self.debug(f"Block type '{tag}' is not supported yet")
        #     raise EthereumError(message=f"Not supported block identifier: {tag}")

        if isinstance(tag, int):
            return

        try:
            tag.strip().lower()
            if tag in ('latest', 'pending', 'earliest'):
                return

            assert tag[:2] == '0x'
            int(tag[2:], 16)
        except (Exception,):
            raise InvalidParamError(message=f'invalid block tag {tag}')

    @staticmethod
    def _normalize_account(account: str) -> str:
        try:
            sender = account.strip().lower()
            bin_sender = bytes.fromhex(sender[2:])
            assert len(bin_sender) == 20

            return sender
        except (Exception,):
            raise InvalidParamError(message='bad account')

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

    def eth_getBalance(self, account: str, tag: str) -> str:
        """account - address to check for balance.
           tag - integer block number, or the string "latest", "earliest" or "pending"
        """

        self._validate_block_tag(tag)
        account = self._normalize_account(account)

        try:
            neon_account_info = self._solana.get_neon_account_info(EthereumAddress(account))
            if neon_account_info is None:
                return hex(0)

            return hex(neon_account_info.balance)
        except (Exception,):
            # self.debug(f"eth_getBalance: Can't get account info: {err}")
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

    def _get_block_by_slot(self, block: SolanaBlockInfo, full: bool, skip_transaction: bool) -> Optional[dict]:
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

    def eth_getStorageAt(self, account: str, position, tag: str) -> str:
        """
        Retrieves storage data by given position
        Currently supports only 'latest' block
        """

        self._validate_block_tag(tag)
        account = self._normalize_account(account)

        try:
            value = neon_cli().call('get-storage-at', account, position)
            return value
        except (Exception,):
            # self.error(f"eth_getStorageAt: Neon-cli failed to execute: {err}")
            return '0x00'

    def _get_block_by_hash(self, block_hash: str) -> SolanaBlockInfo:
        try:
            block_hash = block_hash.strip().lower()
            assert block_hash[:2] == '0x'

            bin_block_hash = bytes.fromhex(block_hash[2:])
            assert len(bin_block_hash) == 32
        except (Exception,):
            raise InvalidParamError(message=f'bad block hash {block_hash}')

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

    def eth_getBlockByNumber(self, tag: str, full: bool) -> Optional[dict]:
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

    def eth_call(self, obj: dict, tag: str) -> str:
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
        self._validate_block_tag(tag)
        if not isinstance(obj, dict):
            raise InvalidParamError(message='invalid object type')

        if not obj['data']:
            raise InvalidParamError(message="missing data")

        try:
            caller_id = obj.get('from', "0x0000000000000000000000000000000000000000")
            contract_id = obj.get('to', 'deploy')
            data = obj.get('data', "None")
            value = obj.get('value', '')
            return "0x"+call_emulated(contract_id, caller_id, data, value)['result']
        except EthereumError:
            raise
        except Exception as err:
            self.error(f"eth_call Exception {err}")
            raise

    def eth_getTransactionCount(self, account: str, tag: str) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_account(account)

        try:
            neon_account_info = self._solana.get_neon_account_info(account)
            return hex(neon_account_info.trx_count)
        except (Exception,):
            # self.debug(f"eth_getTransactionCount: Can't get account info: {err}")
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
        neon_sign = self._normalize_tx_id(NeonTxId)

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

    def eth_getTransactionByHash(self, NeonTxId: str) -> Optional[dict]:
        neon_sign = self._normalize_tx_id(NeonTxId)

        tx = self._db.get_tx_by_neon_sign(neon_sign)
        if tx is None:
            self.debug("Not found receipt")
            return None
        return self._get_transaction(tx)

    def eth_getCode(self, account: str, tag) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_account(account)

        try:
            code_info = self._solana.get_neon_code_info(account)
            if (not code_info) or (not code_info.code):
                return '0x'
            return code_info.code
        except (Exception,):
            return '0x'

    def eth_sendRawTransaction(self, rawTrx: str) -> str:
        try:
            trx = EthTrx.fromString(bytearray.fromhex(rawTrx[2:]))
        except (Exception,):
            raise InvalidParamError(message="wrong transaction format")

        eth_signature = '0x' + trx.hash_signed().hex()
        self.debug(f"sendRawTransaction {eth_signature}: {json.dumps(trx.as_dict(), cls=JsonEncoder, sort_keys=True)}")

        min_gas_price = self.gas_price_calculator.get_min_gas_price()

        self._stat_tx_begin()

        try:
            tx_sender = NeonTxSender(self._db, self._solana, trx, steps=EVM_STEP_COUNT, min_gas_price=min_gas_price)
            tx_sender.execute()
            self._stat_tx_success()
            return eth_signature

        except PendingTxError as err:
            self._stat_tx_failed()
            self.debug(f'{err}')
            return eth_signature
        except EthereumError:
            self._stat_tx_failed()
            raise
        except Exception:
            self._stat_tx_failed()
            raise

    def _stat_tx_begin(self):
        self._stat_exporter.stat_commit_tx_begin()

    def _stat_tx_success(self):
        self._stat_exporter.stat_commit_tx_end_success()

    def _stat_tx_failed(self):
        self._stat_exporter.stat_commit_tx_end_failed(None)

    def _get_transaction_by_index(self, block: SolanaBlockInfo, tx_idx: int) -> Optional[dict]:
        try:
            if isinstance(tx_idx, str):
                tx_idx = int(tx_idx, 16)
            assert tx_idx >= 0
        except (Exception,):
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

    def eth_sign(self, address: str, data: str) -> str:
        address = self._normalize_account(address)
        try:
            data = bytes.fromhex(data[2:])
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

        account = KeyStorage().get_key(address)
        if not account:
            raise EthereumError(message='unknown account')

        message = str.encode(f'\x19Ethereum Signed Message:\n{len(data)}') + data
        return str(account.private.sign_msg(message))

    def eth_signTransaction(self, tx: dict) -> dict:
        if 'from' not in tx:
            raise InvalidParamError(message='no sender in transaction')

        sender = tx['from']
        sender = self._normalize_account(sender)

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
        except (Exception,):
            raise InvalidParamError(message='bad transaction')

    def eth_sendTransaction(self, tx: dict) -> str:
        tx = self.eth_signTransaction(tx)
        return self.eth_sendRawTransaction(tx['raw'])

    @staticmethod
    def web3_sha3(data: str) -> str:
        try:
            data = bytes.fromhex(data[2:])
        except (Exception,):
            raise InvalidParamError(message='data is not hex string')

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
        except (Exception,):
            return False

    def net_peerCount(self) -> str:
        cluster_node_list = self._solana.get_cluster_nodes()
        return hex(len(cluster_node_list))

    @staticmethod
    def net_listening() -> bool:
        return False

    def neon_getSolanaTransactionByNeonTransaction(self, NeonTxId: str) -> Union[str, list]:
        neon_sign = self._normalize_tx_id(NeonTxId)
        return self._db.get_sol_sign_list_by_neon_sign(neon_sign)
