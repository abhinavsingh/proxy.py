import json
import multiprocessing
import traceback
import eth_utils

from typing import Optional, Union, Dict, Any, List, Tuple

import sha3
from logged_groups import logged_group, LogMng
from web3.auto import w3

from ..common_neon.address import EthereumAddress
from ..common_neon.emulator_interactor import call_emulated, call_trx_emulated
from ..common_neon.errors import EthereumError, InvalidParamError
from ..common_neon.estimate import GasEstimate
from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.keys_storage import KeyStorage
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.utils import SolanaBlockInfo, NeonTxReceiptInfo, NeonTxInfo, NeonTxResultInfo
from ..common_neon.gas_price_calculator import GasPriceCalculator
from ..common_neon.elf_params import ElfParams
from ..common_neon.environment_utils import neon_cli
from ..common_neon.environment_data import SOLANA_URL, PP_SOLANA_URL, USE_EARLIEST_BLOCK_IF_0_PASSED
from ..common_neon.environment_data import PYTH_MAPPING_ACCOUNT
from ..common_neon.transaction_validator import NeonTxValidator
from ..indexer.indexer_db import IndexerDB
from ..statistics_exporter.proxy_metrics_interface import StatisticsExporter
from ..mempool import MemPoolClient, MP_SERVICE_ADDR, MPSendTxResult


NEON_PROXY_PKG_VERSION = '0.11.0-dev'
NEON_PROXY_REVISION = 'NEON_PROXY_REVISION_TO_BE_REPLACED'


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        return json.JSONEncoder.default(self, obj)


@logged_group("neon.Proxy")
class NeonRpcApiWorker:
    proxy_id_glob = multiprocessing.Value('i', 0)

    def __init__(self):
        self._solana = SolanaInteractor(SOLANA_URL)
        self._db = IndexerDB()
        self._stat_exporter: Optional[StatisticsExporter] = None
        self._mempool_client = MemPoolClient(MP_SERVICE_ADDR)

        if PP_SOLANA_URL == SOLANA_URL:
            self.gas_price_calculator = GasPriceCalculator(self._solana, PYTH_MAPPING_ACCOUNT)
        else:
            self.gas_price_calculator = GasPriceCalculator(SolanaInteractor(PP_SOLANA_URL), PYTH_MAPPING_ACCOUNT)
        self.gas_price_calculator.update_mapping()
        self.gas_price_calculator.try_update_gas_price()

        with self.proxy_id_glob.get_lock():
            self.proxy_id = self.proxy_id_glob.value
            self.proxy_id_glob.value += 1

        if self.proxy_id == 0:
            self.debug(f'Neon Proxy version: {self.neon_proxy_version()}')
        self.debug(f"Worker id {self.proxy_id}")

    def set_stat_exporter(self, stat_exporter: StatisticsExporter):
        self._stat_exporter = stat_exporter

    @staticmethod
    def neon_proxy_version() -> str:
        return 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION

    @staticmethod
    def web3_clientVersion() -> str:
        return 'Neon/v' + ElfParams().neon_evm_version + '-' + ElfParams().neon_evm_revision

    @staticmethod
    def eth_chainId() -> str:
        return hex(ElfParams().chain_id)

    @staticmethod
    def neon_cli_version() -> str:
        return neon_cli().version()

    @staticmethod
    def net_version() -> str:
        return str(ElfParams().chain_id)

    def eth_gasPrice(self) -> str:
        gas_price = self.gas_price_calculator.get_suggested_gas_price()
        return hex(gas_price)

    def eth_estimateGas(self, param: Dict[str, Any]) -> str:
        if not isinstance(param, dict):
            raise InvalidParamError('invalid param')
        if 'from' in param:
            param['from'] = self._normalize_account(param['from'])
        if 'to' in param:
            param['to'] = self._normalize_account(param['to'])

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

    @staticmethod
    def _should_return_starting_block(tag: Union[str, int]) -> bool:
        return tag == 'earliest' \
            or ((tag == '0x0' or str(tag) == '0') and USE_EARLIEST_BLOCK_IF_0_PASSED)

    def _process_block_tag(self, tag: Union[str, int]) -> SolanaBlockInfo:
        if tag in ("latest", "pending"):
            block = self._db.get_latest_block()
        elif self._should_return_starting_block(tag):
            block = self._db.get_starting_block()
        elif isinstance(tag, str):
            try:
                block = SolanaBlockInfo(block_slot=int(tag.strip(), 16))
            except (Exception,):
                raise InvalidParamError(message=f'failed to parse block tag: {tag}')
        elif isinstance(tag, int):
            block = SolanaBlockInfo(block_slot=tag)
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
    def _validate_block_tag(tag: Union[int, str]) -> None:
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
            assert sender[:2] == '0x'
            sender = sender[2:]

            bin_sender = bytes.fromhex(sender)
            assert len(bin_sender) == 20

            return eth_utils.to_checksum_address(sender)
        except (Exception,):
            raise InvalidParamError(message='bad account')

    def _get_full_block_by_number(self, tag: Union[str, int]) -> SolanaBlockInfo:
        block = self._process_block_tag(tag)
        if block.block_slot is None:
            self.debug(f"Not found block by number {tag}")
            return block

        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.block_slot}")

        return block

    def eth_blockNumber(self) -> str:
        slot = self._db.get_latest_block_slot()
        return hex(slot)

    def eth_getBalance(self, account: str, tag: Union[int, str]) -> str:
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

    def eth_getLogs(self, obj: Dict[str, Any]) -> List[Dict[str, Any]]:
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
            from_block = self._process_block_tag(obj['fromBlock']).block_slot
        if 'toBlock' in obj and obj['toBlock'] not in ('latest', 'pending'):
            to_block = self._process_block_tag(obj['toBlock']).block_slot
        if 'address' in obj:
            addresses = to_list(obj['address'])
        if 'topics' in obj:
            topics = to_list(obj['topics'])
        if 'blockHash' in obj:
            block_hash = obj['blockHash']

        return self._db.get_logs(from_block, to_block, addresses, topics, block_hash)

    def _get_block_by_slot(self, block: SolanaBlockInfo, full: bool, skip_transaction: bool) -> Optional[dict]:
        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                return None

        sig_list = []
        gas_used = 0
        if skip_transaction:
            tx_list = []
        else:
            tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)

        for tx in tx_list:
            gas_used += int(tx.neon_tx_res.gas_used, 16)

            if full:
                receipt = self._get_transaction(tx)
                sig_list.append(receipt)
            else:
                sig_list.append(tx.neon_tx.sig)

        result = {
            "difficulty": '0x20000',
            "totalDifficulty": '0x20000',
            "extraData": "0x" + '0' * 63 + '1',
            "logsBloom": '0x' + '0' * 512,
            "gasLimit": '0xec8563e271ac',
            "transactionsRoot": '0x' + '0' * 63 + '1',
            "receiptsRoot": '0x' + '0' * 63 + '1',
            "stateRoot": '0x' + '0' * 63 + '1',

            "uncles": [],
            "sha3Uncles": '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',

            "miner": '0x' + '0' * 40,
            # 8 byte nonce
            "nonce": '0x0000000000000000',
            "mixHash": '0x' + '0' * 63 + '1',
            "size": '0x' + '0' * 63 + '1',

            "gasUsed": hex(gas_used),
            "hash": block.block_hash,
            "number": hex(block.block_slot),
            "parentHash": block.parent_block_hash,
            "timestamp": hex(block.block_time),
            "transactions": sig_list,
        }
        return result

    def eth_getStorageAt(self, account: str, position, tag: Union[int, str]) -> str:
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
        if block.block_slot is None:
            self.debug("Not found block by hash %s", block_hash)

        return block

    def eth_getBlockByHash(self, block_hash: str, full: bool) -> Optional[dict]:
        """Returns information about a block by hash.
            block_hash - Hash of a block.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block = self._get_block_by_hash(block_hash)
        if block.block_slot is None:
            return None
        ret = self._get_block_by_slot(block, full, False)
        return ret

    def eth_getBlockByNumber(self, tag: Union[int, str], full: bool) -> Optional[dict]:
        """Returns information about a block by block number.
            tag - integer of a block number, or the string "earliest", "latest" or "pending", as in the default block parameter.
            full - If true it returns the full transaction objects, if false only the hashes of the transactions.
        """
        block = self._process_block_tag(tag)
        if block.block_slot is None:
            self.debug(f"Not found block by number {tag}")
            return None
        ret = self._get_block_by_slot(block, full, tag in ('latest', 'pending'))
        return ret

    def eth_call(self, obj: dict, tag: Union[int, str]) -> str:
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

    def eth_getTransactionCount(self, account: str, tag: Union[str, int]) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_account(account).lower()

        try:
            self.debug(f"Get transaction count. Account: {account}, tag: {tag}")

            if tag == "pending":
                req_id = LogMng.get_logging_context().get("req_id")
                pending_tx_nonce = self._mempool_client.get_pending_tx_nonce(req_id=req_id, sender=account)
                self.debug(f"Pending tx count for: {account} - is: {pending_tx_nonce}")
                if pending_tx_nonce is None:
                    pending_tx_nonce = 0
                else:
                    pending_tx_nonce += 1

                neon_account_info = self._solana.get_neon_account_info(account, 'processed')
                tx_count = max(neon_account_info.tx_count, pending_tx_nonce)
            else:
                neon_account_info = self._solana.get_neon_account_info(account, 'confirmed')
                tx_count = neon_account_info.tx_count

            return hex(tx_count)
        except (Exception,):
            # self.debug(f"eth_getTransactionCount: Can't get account info: {err}")
            return hex(0)

    @staticmethod
    def _get_transaction_receipt(tx: NeonTxReceiptInfo) -> dict:
        result = {
            "transactionHash": tx.neon_tx.sig,
            "transactionIndex": hex(tx.neon_tx_res.tx_idx),
            "type": "0x0",
            "blockHash": tx.neon_tx_res.block_hash,
            "blockNumber": hex(tx.neon_tx_res.block_slot),
            "from": tx.neon_tx.addr,
            "to": tx.neon_tx.to_addr,
            "gasUsed": tx.neon_tx_res.gas_used,
            "cumulativeGasUsed": tx.neon_tx_res.gas_used,
            "contractAddress": tx.neon_tx.contract,
            "logs": tx.neon_tx_res.log_list,
            "status": tx.neon_tx_res.status,
            "logsBloom": "0x"+'0'*512
        }

        return result

    def eth_getTransactionReceipt(self, neon_tx_sig: str) -> Optional[dict]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        tx = self._db.get_tx_by_neon_sig(neon_sig)
        if not tx:
            self.debug("Not found receipt")
            return None
        return self._get_transaction_receipt(tx)

    @staticmethod
    def _get_transaction(tx: NeonTxReceiptInfo) -> dict:
        t = tx.neon_tx
        r = tx.neon_tx_res

        block_number = None
        if r.block_slot is not None:
            block_number = hex(r.block_slot)

        tx_idx = None
        if r.tx_idx is not None:
            tx_idx = hex(r.tx_idx)

        result = {
            "blockHash": r.block_hash,
            "blockNumber": block_number,
            "hash": t.sig,
            "transactionIndex": tx_idx,
            "type": "0x0",
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

    def eth_getTransactionByHash(self, neon_tx_sig: str) -> Optional[dict]:
        neon_sig = self._normalize_tx_id(neon_tx_sig)

        neon_tx_receipt: NeonTxReceiptInfo = self._db.get_tx_by_neon_sig(neon_sig)
        if neon_tx_receipt is None:
            req_id = LogMng.get_logging_context().get("req_id")
            neon_tx: NeonTx = self._mempool_client.get_pending_tx_by_hash(req_id, neon_sig)
            if neon_tx is None:
                self.debug("Not found receipt")
                return None
            neon_tx_receipt = NeonTxReceiptInfo(NeonTxInfo(tx=neon_tx), NeonTxResultInfo())
        return self._get_transaction(neon_tx_receipt)

    def eth_getCode(self, account: str, tag: Union[str, int]) -> str:
        self._validate_block_tag(tag)
        account = self._normalize_account(account)

        try:
            code_info = self._solana.get_neon_code_info(account)
            if (not code_info) or (not code_info.code):
                return '0x'
            return code_info.code
        except (Exception,):
            return '0x'

    def eth_sendRawTransaction(self, raw_tx: str) -> str:
        try:
            neon_tx = NeonTx.fromString(bytearray.fromhex(raw_tx[2:]))
        except (Exception,):
            raise InvalidParamError(message="wrong transaction format")

        neon_sender = '0x' + neon_tx.sender()
        neon_signature = '0x' + neon_tx.hash_signed().hex()
        self.debug(f"sendRawTransaction {neon_signature}: {json.dumps(neon_tx.as_dict(), cls=JsonEncoder)}")

        self._stat_tx_begin()
        try:
            min_gas_price = self.gas_price_calculator.get_min_gas_price()
            neon_tx_validator = NeonTxValidator(self._solana, neon_tx, min_gas_price)
            neon_tx_exec_cfg = neon_tx_validator.precheck()

            req_id = LogMng.get_logging_context().get("req_id")

            sender_tx_cnt = 0
            result: Optional[MPSendTxResult] = None
            for i in range(2):
                neon_account_info = self._solana.get_neon_account_info(neon_sender, commitment='processed')
                sender_tx_cnt = neon_account_info.tx_count if neon_account_info is not None else 0
                neon_tx_validator.prevalidate_tx_nonce(sender_tx_cnt)
                if (result is not None) and (sender_tx_cnt != neon_tx.nonce):
                    result.last_nonce = None
                    break

                result: MPSendTxResult = self._mempool_client.send_raw_transaction(
                    req_id=req_id, signature=neon_signature, neon_tx=neon_tx, sender_tx_cnt=sender_tx_cnt,
                    neon_tx_exec_cfg=neon_tx_exec_cfg
                )
                if result.success or (result.last_nonce != -1):
                    break

            if result.success:
                self._stat_tx_success()
                return neon_signature
            else:
                if result.last_nonce is not None:
                    sender_tx_cnt = result.last_nonce + 1
                neon_tx_validator.raise_nonce_error(sender_tx_cnt, neon_tx.nonce)

        except EthereumError:
            self._stat_tx_failed()
            raise

        except Exception as err:
            self.error(f"Failed to process eth_sendRawTransaction, Error: {err}")
            self._stat_tx_failed()
            raise

    def _stat_tx_begin(self):
        self._stat_exporter.stat_commit_tx_begin()

    def _stat_tx_success(self):
        self._stat_exporter.stat_commit_tx_end_success()

    def _stat_tx_failed(self):
        self._stat_exporter.stat_commit_tx_end_failed(None)

    def _get_transaction_by_index(self, block: SolanaBlockInfo, tx_idx: Union[str, int]) -> Optional[Dict[str, Any]]:
        try:
            if isinstance(tx_idx, str):
                tx_idx = int(tx_idx, 16)
            assert tx_idx >= 0
        except (Exception,):
            raise EthereumError(message=f'invalid transaction index {tx_idx}')

        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.block_slot}")
                return None

        return self._db.get_tx_by_block_slot_tx_idx(block.block_slot, tx_idx)

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
        if block.block_slot is None:
            return hex(0)
        if block.is_empty():
            block = self._db.get_block_by_slot(block.block_slot)
            if block.is_empty():
                self.debug(f"Not found block by slot {block.block_slot}")
                return hex(0)

        tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)
        return hex(len(tx_list))

    def eth_getBlockTransactionCountByNumber(self, tag: str) -> str:
        block = self._get_full_block_by_number(tag)
        if block.is_empty():
            return hex(0)

        tx_list = self._db.get_tx_list_by_block_slot(block.block_slot)
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

    def eth_signTransaction(self, tx: Dict[str, Any]) -> Dict[str, Any]:
        if 'from' not in tx:
            raise InvalidParamError(message='no sender in transaction')

        sender = tx['from']
        del tx['from']
        sender = self._normalize_account(sender)

        if 'to' in tx:
            tx['to'] = self._normalize_account(tx['to'])

        account = KeyStorage().get_key(sender)
        if not account:
            raise EthereumError(message='unknown account')

        if 'nonce' not in tx:
            tx['nonce'] = self.eth_getTransactionCount(sender, 'pending')

        if 'chainId' not in tx:
            tx['chainId'] = hex(ElfParams().chain_id)

        try:
            signed_tx = w3.eth.account.sign_transaction(tx, account.private)
            raw_tx = signed_tx.rawTransaction.hex()

            tx['from'] = sender
            tx['to'] = NeonTx.fromString(bytearray.fromhex(raw_tx[2:])).toAddress.hex()
            tx['hash'] = signed_tx.hash.hex()
            tx['r'] = hex(signed_tx.r)
            tx['s'] = hex(signed_tx.s)
            tx['v'] = hex(signed_tx.v)

            return {
                'raw': raw_tx,
                'tx': tx
            }
        except Exception as e:
            err_tb = "".join(traceback.format_tb(e.__traceback__))
            self.error(f'Exception {type(e)}({str(e)}: {err_tb}')
            raise InvalidParamError(message='bad transaction')

    def eth_sendTransaction(self, tx: Dict[str, Any]) -> str:
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
            if (slots_behind == 0) or (slots_behind is None) or (latest_slot is None) or (first_slot is None):
                return False

            return {
                'startingBlock': first_slot,
                'currentBlock': latest_slot,
                'highestBlock': latest_slot + slots_behind
            }
        except (Exception,):
            return False

    def net_peerCount(self) -> str:
        cluster_node_list = self._solana.get_cluster_nodes()
        return hex(len(cluster_node_list))

    @staticmethod
    def net_listening() -> bool:
        return False

    def neon_getSolanaTransactionByNeonTransaction(self, neon_tx_id: str) -> Union[str, list]:
        neon_sig = self._normalize_tx_id(neon_tx_id)
        return self._db.get_sol_sig_list_by_neon_sig(neon_sig)

    def neon_emulate(self, raw_signed_tx: str):
        """Executes emulator with given transaction
        """
        self.debug(f"Call neon_emulate: {raw_signed_tx}")
        neon_tx = NeonTx.fromString(bytearray.fromhex(raw_signed_tx))
        emulation_result = call_trx_emulated(neon_tx)
        return emulation_result

    def neon_finalizedBlockNumber(self) -> str:
        slot = self._db.get_finalized_block_slot()
        return hex(slot)

    def neon_getEvmParams(self)-> Dict[str, Any]:
        """Returns map of Neon-EVM parameters"""
        self.debug(f"call neon_getEvmParams")
        return ElfParams().get_params()
