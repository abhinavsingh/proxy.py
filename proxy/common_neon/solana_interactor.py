from __future__ import annotations

import math

import base58
import base64
import time
import traceback
import requests
import json

from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.rpc.types import RPCResponse
from solana.transaction import Transaction
from itertools import zip_longest
from logged_groups import logged_group
from typing import Dict, Union, Any, List, NamedTuple, Optional, Tuple, cast
from base58 import b58decode, b58encode

from .utils import SolanaBlockInfo
from .environment_data import EVM_LOADER_ID, RETRY_ON_FAIL, FUZZING_BLOCKHASH, FINALIZED

from ..common_neon.layouts import ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT, STORAGE_ACCOUNT_INFO_LAYOUT
from ..common_neon.layouts import ACCOUNT_LOOKUP_TABLE_LAYOUT
from ..common_neon.constants import CONTRACT_ACCOUNT_TAG, ACTIVE_STORAGE_TAG, NEON_ACCOUNT_TAG, LOOKUP_ACCOUNT_TAG
from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.utils import get_from_dict


class AccountInfo(NamedTuple):
    tag: int
    lamports: int
    owner: PublicKey
    data: bytes


class NeonAccountInfo(NamedTuple):
    pda_address: PublicKey
    ether: str
    nonce: int
    trx_count: int
    balance: int
    code_account: Optional[PublicKey]
    is_rw_blocked: bool
    ro_blocked_cnt: int

    @staticmethod
    def frombytes(pda_address: PublicKey, data: bytes) -> NeonAccountInfo:
        cont = ACCOUNT_INFO_LAYOUT.parse(data)

        code_account = None
        if cont.code_account != bytes().rjust(PublicKey.LENGTH, b"\0"):
            code_account = PublicKey(cont.code_account)

        return NeonAccountInfo(
            pda_address=pda_address,
            ether=cont.ether.hex(),
            nonce=cont.nonce,
            trx_count=int.from_bytes(cont.trx_count, "little"),
            balance=int.from_bytes(cont.balance, "little"),
            code_account=code_account,
            is_rw_blocked=(cont.is_rw_blocked != 0),
            ro_blocked_cnt=cont.ro_blocked_cnt
        )


class NeonCodeInfo(NamedTuple):
    pda_address: PublicKey
    owner: PublicKey
    code_size: int
    generation: int
    code: Optional[str]

    @staticmethod
    def frombytes(pda_address: PublicKey, data: bytes) -> NeonCodeInfo:
        cont = CODE_ACCOUNT_INFO_LAYOUT.parse(data)

        offset = CODE_ACCOUNT_INFO_LAYOUT.sizeof()
        code = None
        if len(data) >= offset + cont.code_size:
            code = '0x' + data[offset:][:cont.code_size].hex()

        return NeonCodeInfo(
            pda_address=pda_address,
            owner=PublicKey(cont.owner),
            code_size=cont.code_size,
            generation=cont.generation,
            code=code
        )


class StorageAccountInfo(NamedTuple):
    storage_account: PublicKey
    tag: int
    caller: str
    nonce: int
    gas_limit: int
    gas_price: int
    block_slot: int
    operator: PublicKey
    account_list_len: int
    executor_data_size: int
    evm_data_size: int
    gas_used_and_paid: int
    number_of_payments: int
    sig: bytes
    account_list: List[Tuple[bool, str]]

    @staticmethod
    def frombytes(storage_account: PublicKey, data: bytes) -> StorageAccountInfo:
        storage = STORAGE_ACCOUNT_INFO_LAYOUT.parse(data)

        account_list: List[Tuple[bool, str]] = []
        offset = STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.account_list_len):
            writable = (data[offset] > 0)
            offset += 1

            some_pubkey = PublicKey(data[offset:offset + PublicKey.LENGTH])
            offset += PublicKey.LENGTH

            account_list.append((writable, str(some_pubkey)))

        return StorageAccountInfo(
            storage_account=storage_account,
            tag=storage.tag,
            caller=storage.caller.hex(),
            nonce=storage.nonce,
            gas_limit=int.from_bytes(storage.gas_limit, "little"),
            gas_price=int.from_bytes(storage.gas_price, "little"),
            block_slot=storage.block_slot,
            operator=PublicKey(storage.operator),
            account_list_len=storage.account_list_len,
            executor_data_size=storage.executor_data_size,
            evm_data_size=storage.evm_data_size,
            gas_used_and_paid=int.from_bytes(storage.gas_used_and_paid, "little"),
            number_of_payments=storage.number_of_payments,
            sig=storage.sig,
            account_list=account_list
        )


class AddressLookupTableAccountInfo(NamedTuple):
    type: int
    table_account: PublicKey
    deactivation_slot: int
    last_extended_slot: int
    last_extended_slot_start_index: int
    authority: Optional[PublicKey]
    account_key_list: List[PublicKey]

    @staticmethod
    def frombytes(table_account: PublicKey, data: bytes) -> Optional[AddressLookupTableAccountInfo]:
        lookup = ACCOUNT_LOOKUP_TABLE_LAYOUT.parse(data)
        if lookup.type != LOOKUP_ACCOUNT_TAG:
            return None

        offset = ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()
        if (len(data) - offset) % PublicKey.LENGTH:
            return None

        account_key_list = []
        account_key_list_len = math.ceil((len(data) - offset) / PublicKey.LENGTH)
        for _ in range(account_key_list_len):
            some_pubkey = PublicKey(data[offset:offset + PublicKey.LENGTH])
            offset += PublicKey.LENGTH
            account_key_list.append(some_pubkey)

        authority = PublicKey(lookup.authority) if lookup.has_authority else None

        return AddressLookupTableAccountInfo(
            type=lookup.type,
            table_account=table_account,
            deactivation_slot=lookup.deactivation_slot,
            last_extended_slot=lookup.last_extended_slot,
            last_extended_slot_start_index=lookup.last_extended_slot_start_index,
            authority=authority,
            account_key_list=account_key_list
        )


class SendResult(NamedTuple):
    error: dict
    result: Optional[str]


@logged_group("neon.Proxy")
class SolanaInteractor:
    def __init__(self, solana_url: str) -> None:
        self._client = SolanaClient(solana_url)._provider
        self._fuzzing_hash_cycle = False

    def _send_post_request(self, request) -> RPCResponse:
        """This method is used to make retries to send request to Solana"""

        headers = {
            "Content-Type": "application/json"
        }
        client = self._client

        retry = 0
        while True:
            try:
                retry += 1
                raw_response = client.session.post(client.endpoint_uri, headers=headers, json=request)
                raw_response.raise_for_status()
                return raw_response

            except requests.exceptions.RequestException as err:
                # Hide the Solana URL
                str_err = str(err).replace(client.endpoint_uri, 'XXXXX')

                if retry <= RETRY_ON_FAIL:
                    self.debug(f'Receive connection error {str_err} on connection to Solana. ' +
                               f'Attempt {retry + 1} to send the request to Solana node...')
                    time.sleep(1)
                    continue

                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error(f'Connection exception({retry}) on send request to Solana. Retry {retry}' +
                           f'Type(err): {type(err)}, Error: {str_err}, Traceback: {err_tb}')
                raise Exception(str_err)

            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error('Unknown exception on send request to Solana. ' +
                           f'Type(err): {type(err)}, Error: {str(err)}, Traceback: {err_tb}')
                raise

    def _send_rpc_request(self, method: str, *params: Any) -> RPCResponse:
        request_id = next(self._client._request_counter) + 1

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }
        raw_response = self._send_post_request(request)
        return cast(RPCResponse, raw_response.json())

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        full_request_list = []
        full_response_list = []
        request_list = []
        request_data = ''
        client = self._client

        for params in params_list:
            request_id = next(client._request_counter) + 1
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            request_list.append(request)
            request_data += ', ' + json.dumps(request)
            full_request_list.append(request)

            # Protection from big payload
            if len(request_data) >= 48 * 1024 or len(full_request_list) == len(params_list):
                raw_response = self._send_post_request(request_list)
                response_data = cast(List[RPCResponse], raw_response.json())

                full_response_list += response_data
                request_list.clear()
                request_data = ''

        full_response_list.sort(key=lambda r: r["id"])

        for request, response in zip_longest(full_request_list, full_response_list):
            # self.debug(f'Request: {request}')
            # self.debug(f'Response: {response}')
            if request["id"] != response["id"]:
                raise RuntimeError(f"Invalid RPC response: request {request} response {response}")

        return full_response_list

    def get_cluster_nodes(self) -> [dict]:
        return self._send_rpc_request("getClusterNodes").get('result', [])

    def get_slots_behind(self) -> Optional[int]:
        response = self._send_rpc_request('getHealth')
        status = response.get('result')
        if status == 'ok':
            return 0
        slots_behind = get_from_dict(response, 'error', 'data', 'numSlotsBehind')
        if slots_behind:
            return int(slots_behind)
        return None

    def is_healthy(self) -> bool:
        status = self._send_rpc_request('getHealth').get('result', 'bad')
        return status == 'ok'

    def get_signatures_for_address(self, before: Optional[str], limit: int, commitment='confirmed') -> []:
        opts: Dict[str, Union[int, str]] = {
            "limit": limit,
            "commitment": commitment
        }

        if before:
            opts["before"] = before

        return self._send_rpc_request("getSignaturesForAddress", EVM_LOADER_ID, opts)

    def get_block_slot(self, commitment='confirmed') -> int:
        opts = {
            'commitment': commitment
        }
        return self._send_rpc_request('getSlot', opts)['result']

    def get_account_info(self, pubkey: PublicKey, length=256, commitment='processed') -> Optional[AccountInfo]:
        opts = {
            "encoding": "base64",
            "commitment": commitment,
        }

        if length != 0:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        result = self._send_rpc_request('getAccountInfo', str(pubkey), opts)
        # self.debug(f"{json.dumps(result, sort_keys=True)}")

        info = result['result']['value']
        if info is None:
            self.debug(f"Can't get information about {str(pubkey)}")
            return None

        data = base64.b64decode(info['data'][0])

        account_tag = data[0]
        lamports = info['lamports']
        owner = PublicKey(info['owner'])

        return AccountInfo(account_tag, lamports, owner, data)

    def get_account_info_list(self, src_account_list: List[PublicKey], length=256,
                              commitment='processed') -> List[AccountInfo]:
        opts = {
            "encoding": "base64",
            "commitment": commitment,
        }

        if length != 0:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        account_info_list = []
        while len(src_account_list) > 0:
            account_list = [str(a) for a in src_account_list[:50]]
            src_account_list = src_account_list[50:]
            result = self._send_rpc_request("getMultipleAccounts", account_list, opts)

            error = result.get('error', None)
            if error:
                self.debug(f"Can't get information about accounts {account_list}: {error}")
                return account_info_list

            for pubkey, info in zip(account_list, result['result']['value']):
                if info is None:
                    account_info_list.append(None)
                else:
                    data = base64.b64decode(info['data'][0])
                    lamports = info['lamports']
                    owner = PublicKey(info['owner'])
                    account_info = AccountInfo(tag=data[0], lamports=lamports, owner=owner, data=data)
                    account_info_list.append(account_info)
        return account_info_list

    def get_sol_balance(self, account, commitment='processed') -> int:
        opts = {
            "commitment": commitment
        }
        return self._send_rpc_request('getBalance', str(account), opts)['result']['value']

    def get_sol_balance_list(self, accounts_list: List[Union[str, PublicKey]], commitment='processed') -> List[int]:
        opts = {
            'commitment': commitment
        }
        requests_list = []
        for account in accounts_list:
            requests_list.append((str(account), opts))

        balances_list = []
        response_list = self._send_rpc_batch_request('getBalance', requests_list)
        for response in response_list:
            value = get_from_dict(response, 'result', 'value')
            balance = int(value) if value else 0
            balances_list.append(balance)

        return balances_list

    def get_token_account_balance(self, pubkey: Union[str, PublicKey], commitment='processed') -> int:
        opts = {
            "commitment": commitment
        }
        response = self._send_rpc_request("getTokenAccountBalance", str(pubkey), opts)
        result = response.get('result', None)
        if result is None:
            return 0
        return int(result['value']['amount'])

    def get_token_account_balance_list(self, pubkey_list: List[Union[str, PublicKey]],
                                       commitment: object = 'processed') -> List[int]:
        opts = {
            "commitment": commitment
        }
        request_list = []
        for pubkey in pubkey_list:
            request_list.append((str(pubkey), opts))

        balance_list = []
        response_list = self._send_rpc_batch_request('getTokenAccountBalance', request_list)
        for response in response_list:
            result = response.get('result', None)
            balance = int(result['value']['amount']) if result else 0
            balance_list.append(balance)

        return balance_list

    def get_neon_account_info(self, eth_account: Union[str, EthereumAddress], commitment='processed') -> Optional[NeonAccountInfo]:
        if isinstance(eth_account, str):
            eth_account = EthereumAddress(eth_account)
        account_sol, nonce = ether2program(eth_account)
        info = self.get_account_info(account_sol, commitment=commitment)
        if info is None:
            return None
        elif info.tag != NEON_ACCOUNT_TAG:
            raise RuntimeError(f"Wrong tag {info.tag} for neon account info {str(account_sol)}")
        elif len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for account data {account_sol}: " +
                               f"{len(info.data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return NeonAccountInfo.frombytes(account_sol, info.data)

    def get_neon_code_info(self, account: Union[str, EthereumAddress, NeonAccountInfo, PublicKey, None]) -> Optional[NeonCodeInfo]:
        if isinstance(account, str) or isinstance(account, EthereumAddress):
            account = self.get_neon_account_info(account)
        if isinstance(account, NeonAccountInfo):
            account = account.code_account
        if not isinstance(account, PublicKey):
            return None

        info = self.get_account_info(account, length=0)
        if info is None:
            return None
        elif info.tag != CONTRACT_ACCOUNT_TAG:
            raise RuntimeError(f"Wrong tag {info.tag} for code account {str(account)}")
        elif len(info.data) < CODE_ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for account data {str(account)}: " +
                               f"{len(info.data)} < {CODE_ACCOUNT_INFO_LAYOUT.sizeof()}")
        return NeonCodeInfo.frombytes(account, info.data)

    def get_neon_account_info_list(self, eth_accounts: List[EthereumAddress]) -> List[Optional[NeonAccountInfo]]:
        requests_list = []
        for eth_account in eth_accounts:
            account_sol, _nonce = ether2program(eth_account)
            requests_list.append(account_sol)
        responses_list = self.get_account_info_list(requests_list)
        accounts_list = []
        for account_sol, info in zip(requests_list, responses_list):
            if info is None or len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof() or info.tag != NEON_ACCOUNT_TAG:
                accounts_list.append(None)
                continue
            accounts_list.append(NeonAccountInfo.frombytes(account_sol, info.data))
        return accounts_list

    def get_storage_account_info(self, storage_account: PublicKey) -> Optional[StorageAccountInfo]:
        info = self.get_account_info(storage_account, length=0)
        if info is None:
            return None
        elif info.tag != ACTIVE_STORAGE_TAG:
            self.debug(f'Storage account {str(storage_account)} has tag {info.tag}')
            return None
        elif len(info.data) < STORAGE_ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for storage data {str(storage_account)}: " +
                               f"{len(info.data)} < {STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()}")
        return StorageAccountInfo.frombytes(storage_account, info.data)

    def get_account_lookup_table_info(self, table_account: PublicKey) -> Optional[AddressLookupTableAccountInfo]:
        info = self.get_account_info(table_account, length=0)
        if info is None:
            return None
        elif len(info.data) < ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for lookup table data {str(table_account)}: " +
                               f"{len(info.data)} < {ACCOUNT_LOOKUP_TABLE_LAYOUT.sizeof()}")
        return AddressLookupTableAccountInfo.frombytes(table_account, info.data)

    def get_multiple_rent_exempt_balances_for_size(self, size_list: List[int], commitment='confirmed') -> List[int]:
        opts = {
            "commitment": commitment
        }
        request_list = [(size, opts) for size in size_list]
        response_list = self._send_rpc_batch_request("getMinimumBalanceForRentExemption", request_list)
        return [r['result'] for r in response_list]

    def get_block_slot_list(self, last_block_slot: int, limit: int, commitment='confirmed') -> [int]:
        opts = {
            "commitment": commitment,
            "enconding": "json",
        }
        return self._send_rpc_request("getBlocksWithLimit", last_block_slot, limit, opts)['result']

    def get_block_info(self, block_slot: int, commitment='confirmed') -> SolanaBlockInfo:
        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }

        response = self._send_rpc_request('getBlock', block_slot, opts)
        net_block = response.get('result', None)
        if not net_block:
            return SolanaBlockInfo(block_slot=block_slot)

        return SolanaBlockInfo(
            block_slot=block_slot,
            block_hash='0x' + base58.b58decode(net_block['blockhash']).hex().lower(),
            block_time=net_block['blockTime'],
            parent_block_slot=net_block['parentSlot']
        )

    def get_block_info_list(self, block_slot_list: List[int], commitment='confirmed') -> List[SolanaBlockInfo]:
        block_list = []
        if not len(block_slot_list):
            return block_list

        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }

        request_list = []
        for slot in block_slot_list:
            request_list.append((slot, opts))

        response_list = self._send_rpc_batch_request('getBlock', request_list)
        for block_slot, response in zip(block_slot_list, response_list):
            if (not response) or ('result' not in response):
                block = SolanaBlockInfo(block_slot=block_slot)
            else:
                net_block = response['result']
                block = SolanaBlockInfo(
                    block_slot=block_slot,
                    block_hash='0x' + base58.b58decode(net_block['blockhash']).hex().lower(),
                    block_time=net_block['blockTime'],
                    parent_block_slot=net_block['parentSlot']
                )
            block_list.append(block)
        return block_list

    def get_recent_blockslot(self, commitment='confirmed', default: Optional[int] = None) -> int:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getLatestBlockhash', opts)
        if not blockhash_resp.get("result"):
            if default:
                return default
            self.debug(f'{blockhash_resp}')
            raise RuntimeError("failed to get latest blockhash")
        return blockhash_resp['result']['context']['slot']

    def get_recent_blockhash(self, commitment='confirmed') -> Blockhash:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getLatestBlockhash', opts)
        if not blockhash_resp.get("result"):
            raise RuntimeError("failed to get recent blockhash")
        blockhash = blockhash_resp["result"]["value"]["blockhash"]
        return Blockhash(blockhash)

    def get_block_height(self, commitment='confirmed') -> int:
        opts = {
            'commitment': commitment
        }
        blockheight_resp = self._send_rpc_request('getBlockHeight', opts)
        return blockheight_resp['result']

    def _fuzzing_transactions(self, signer: SolanaAccount,
                              tx_list: List[Transaction], tx_opts: Dict[str, str],
                              request_list: List[Tuple[str, Dict[str, str]]]) -> List[Tuple[str, Dict[str, str]]]:
        """
        Make each second transaction a bad one.
        This is used to test a transaction sending on a live cluster (testnet/devnet).
        """
        if not FUZZING_BLOCKHASH:
            return request_list

        self._fuzzing_hash_cycle = not self._fuzzing_hash_cycle
        if not self._fuzzing_hash_cycle:
            return request_list

        # get bad block slot for sent transactions
        slot = self.get_recent_blockslot()
        # blockhash = '4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4'
        block_opts = {
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }
        slot = max(slot - 500, 10)
        block = self._send_rpc_request("getBlock", slot, block_opts)
        fuzzing_blockhash = Blockhash(block['result']['blockhash'])
        self.debug(f"fuzzing block {fuzzing_blockhash} for slot {slot}")

        # sign half of transactions with a bad blockhash
        for idx, tx in enumerate(tx_list):
            if idx % 2 == 1:
                continue
            tx.recent_blockhash = fuzzing_blockhash
            tx.sign(signer)
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list[idx] = (base64_tx, tx_opts)
        return request_list

    def send_multiple_transactions(self, signer: SolanaAccount, tx_list: List[Transaction],
                                   skip_preflight: bool, preflight_commitment: str) -> List[SendResult]:
        opts = {
            "skipPreflight": skip_preflight,
            "encoding": "base64",
            "preflightCommitment": preflight_commitment
        }

        blockhash = None
        request_list = []

        for tx in tx_list:
            if not tx.recent_blockhash:
                if not blockhash:
                    blockhash = self.get_recent_blockhash()
                tx.recent_blockhash = blockhash
                tx.signatures.clear()
            if not tx.signatures:
                tx.sign(signer)
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list.append((base64_tx, opts))

        request_list = self._fuzzing_transactions(signer, tx_list, opts, request_list)
        response_list = self._send_rpc_batch_request('sendTransaction', request_list)
        result_list = []

        for response, tx in zip(response_list, tx_list):
            raw_result = response.get('result')

            result = None
            if isinstance(raw_result, dict):
                self.debug(f'Got strange result on transaction execution: {json.dumps(raw_result)}')
            elif isinstance(raw_result, str):
                result = b58encode(b58decode(raw_result)).decode("utf-8")
            elif isinstance(raw_result, bytes):
                result = b58encode(raw_result).decode("utf-8")
            elif raw_result is not None:
                self.debug(f'Got strange result on transaction execution: {str(raw_result)}')

            error = response.get('error')
            if error:
                if get_from_dict(error, 'data', 'err') == 'AlreadyProcessed':
                    result = b58encode(tx.signature()).decode("utf-8")
                    self.debug(f'Transaction is already processed: {str(result)}')
                    error = None
                else:
                    self.debug(f'Got error on transaction execution: {json.dumps(error)}')
                    result = None

            result_list.append(SendResult(result=result, error=error))
        return result_list

    def get_confirmed_slot_for_multiple_transactions(self, sig_list: List[str]) -> Tuple[int, bool]:
        opts = {
            "searchTransactionHistory": False
        }

        block_slot = 0
        while len(sig_list):
            (part_sig_list, sig_list) = (sig_list[:100], sig_list[100:])
            response = self._send_rpc_request("getSignatureStatuses", part_sig_list, opts)

            result = response.get('result', None)
            if not result:
                return block_slot, False

            block_slot = result['context']['slot']

            for status in result['value']:
                if not status:
                    return block_slot, False
                if status['confirmationStatus'] == 'processed':
                    return block_slot, False

        return block_slot, (block_slot != 0)

    def get_multiple_receipts(self, sig_list: List[str], commitment='confirmed') -> List[Optional[Dict]]:
        if not len(sig_list):
            return []
        opts = {
            "encoding": "json",
            "commitment": commitment,
            "maxSupportedTransactionVersion": 0
        }
        request_list = [(sig, opts) for sig in sig_list]
        response_list = self._send_rpc_batch_request("getTransaction", request_list)
        return [r.get('result') for r in response_list]
