from __future__ import annotations

import base58
import base64
import json
import re
import time
import traceback
import requests

from typing import Optional

from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.rpc.types import RPCResponse
from solana.transaction import Transaction
from itertools import zip_longest
from logged_groups import logged_group
from typing import Dict, Union, Any, List, NamedTuple, cast
from base58 import b58decode, b58encode

from .costs import update_transaction_cost
from .utils import get_from_dict, SolanaBlockInfo
from ..environment import EVM_LOADER_ID, CONFIRMATION_CHECK_DELAY, WRITE_TRANSACTION_COST_IN_DB, SKIP_PREFLIGHT
from ..environment import LOG_SENDING_SOLANA_TRANSACTION, FUZZING_BLOCKHASH, CONFIRM_TIMEOUT, FINALIZED
from ..environment import RETRY_ON_FAIL

from ..common_neon.layouts import ACCOUNT_INFO_LAYOUT
from ..common_neon.address import EthereumAddress, ether2program
from ..common_neon.address import AccountInfoLayout as AccountInfoLayout


class SolTxError(Exception):
    def __init__(self, receipt):
        self.result = receipt
        error = get_error_definition_from_receipt(receipt)
        if isinstance(error, list) and isinstance(error[1], str):
            super().__init__(str(error[1]))
            self.error = str(error[1])
        else:
            super().__init__('Unknown error')
            self.error = json.dumps(receipt)


class AccountInfo(NamedTuple):
    tag: int
    lamports: int
    owner: PublicKey
    data: bytes


class SendResult(NamedTuple):
    error: dict
    result: dict


@logged_group("neon.Proxy")
class SolanaInteractor:
    def __init__(self, solana_url: str) -> None:
        self._client = SolanaClient(solana_url)._provider
        self._fuzzing_hash_cycle = False

    def _make_request(self, request) -> RPCResponse:
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

            except requests.exceptions.ConnectionError as err:
                if retry > RETRY_ON_FAIL:
                    raise

                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error(f'ConnectionError({retry}) on send request to Solana. ' +
                           f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
                time.sleep(1)

            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.error('Unknown exception on send request to Solana. ' +
                           f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
                raise

    def _send_rpc_request(self, method: str, *params: Any) -> RPCResponse:
        request_id = next(self._client._request_counter) + 1

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }
        raw_response = self._make_request(request)
        return cast(RPCResponse, raw_response.json())

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        full_request_data = []
        full_response_data = []
        request_data = []
        client = self._client

        for params in params_list:
            request_id = next(client._request_counter) + 1
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            request_data.append(request)
            full_request_data.append(request)

            # Protection from big payload
            if len(request_data) == 30 or len(full_request_data) == len(params_list):
                raw_response = self._make_request(request_data)
                response_data = cast(List[RPCResponse], raw_response.json())

                full_response_data += response_data
                request_data.clear()

        full_response_data.sort(key=lambda r: r["id"])

        for request, response in zip_longest(full_request_data, full_response_data):
            # self.debug(f'Request: {request}')
            # self.debug(f'Response: {response}')
            if request["id"] != response["id"]:
                raise RuntimeError(f"Invalid RPC response: request {request} response {response}")

        return full_response_data

    def get_signatures_for_address(self, before, until, commitment='confirmed'):
        opts: Dict[str, Union[int, str]] = {}
        if until is not None:
            opts["until"] = until
        if before is not None:
            opts["before"] = before
        opts["commitment"] = commitment
        return self._send_rpc_request("getSignaturesForAddress", EVM_LOADER_ID, opts)

    def get_confirmed_transaction(self, sol_sign: str, encoding: str = "json"):
        return self._send_rpc_request("getConfirmedTransaction", sol_sign, encoding)

    def get_slot(self, commitment='confirmed') -> RPCResponse:
        opts = {
            'commitment': commitment
        }
        return self._send_rpc_request('getSlot', opts)

    def get_account_info(self, pubkey: PublicKey, length=256, commitment='confirmed') -> Optional[AccountInfo]:
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
        self.debug(f"{json.dumps(result, sort_keys=True)}")

        info = result['result']['value']
        if info is None:
            self.debug(f"Can't get information about {str(pubkey)}")
            return None

        data = base64.b64decode(info['data'][0])

        account_tag = data[0]
        lamports = info['lamports']
        owner = info['owner']

        return AccountInfo(account_tag, lamports, owner, data)

    def get_account_info_list(self, accounts: [PublicKey], length=256, commitment='confirmed') -> [AccountInfo]:
        opts = {
            "encoding": "base64",
            "commitment": commitment,
        }

        if length != 0:
            opts['dataSlice'] = {
                'offset': 0,
                'length': length
            }

        result = self._send_rpc_request("getMultipleAccounts", [str(a) for a in accounts], opts)
        self.debug(f"{json.dumps(result, sort_keys=True)}")

        if result['result']['value'] is None:
            self.debug(f"Can't get information about {accounts}")
            return []

        accounts_info = []
        for pubkey, info in zip(accounts, result['result']['value']):
            if info is None:
                accounts_info.append(None)
            else:
                data = base64.b64decode(info['data'][0])
                account = AccountInfo(tag=data[0], lamports=info['lamports'], owner=info['owner'], data=data)
                accounts_info.append(account)

        return accounts_info

    def get_sol_balance(self, account, commitment='confirmed'):
        opts = {
            "commitment": commitment
        }
        return self._send_rpc_request('getBalance', str(account), opts)['result']['value']

    def get_token_account_balance(self, pubkey: Union[str, PublicKey], commitment='confirmed') -> int:
        opts = {
            "commitment": commitment
        }
        response = self._send_rpc_request("getTokenAccountBalance", str(pubkey), opts)
        result = response.get('result', None)
        if result is None:
            return 0
        return int(result['value']['amount'])

    def get_token_account_balance_list(self, pubkey_list: [Union[str, PublicKey]], commitment: object = 'confirmed') -> [int]:
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

    def get_account_info_layout(self, eth_account: EthereumAddress) -> Optional[AccountInfoLayout]:
        account_sol, nonce = ether2program(eth_account)
        info = self.get_account_info(account_sol)
        if info is None:
            return None
        elif len(info.data) < ACCOUNT_INFO_LAYOUT.sizeof():
            raise RuntimeError(f"Wrong data length for account data {account_sol}: " +
                               f"{len(info.data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return AccountInfoLayout.frombytes(info.data)

    def get_multiple_rent_exempt_balances_for_size(self, size_list: [int], commitment='confirmed') -> [int]:
        opts = {
            "commitment": commitment
        }
        request_list = [(size, opts) for size in size_list]
        response_list = self._send_rpc_batch_request("getMinimumBalanceForRentExemption", request_list)
        return [r['result'] for r in response_list]

    def get_block_slot_list(self, last_block_slot, limit: int, commitment='confirmed') -> [int]:
        opts = {
            "commitment": commitment,
            "enconding": "json",
        }
        return self._send_rpc_request("getBlocksWithLimit", last_block_slot, limit, opts)['result']

    def get_block_info(self, slot: int, commitment='confirmed') -> [SolanaBlockInfo]:
        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "signatures",
            "rewards": False
        }

        response = self._send_rpc_request('getBlock', slot, opts)
        net_block = response.get('result', None)
        if not net_block:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            slot=slot,
            finalized=(commitment == FINALIZED),
            hash='0x' + base58.b58decode(net_block['blockhash']).hex(),
            parent_hash='0x' + base58.b58decode(net_block['previousBlockhash']).hex(),
            time=net_block['blockTime'],
            signs=net_block['signatures']
        )

    def get_block_info_list(self, block_slot_list: [int], commitment='confirmed') -> [SolanaBlockInfo]:
        block_list = []
        if not len(block_slot_list):
            return block_list

        opts = {
            "commitment": commitment,
            "encoding": "json",
            "transactionDetails": "signatures",
            "rewards": False
        }

        request_list = []
        for slot in block_slot_list:
            request_list.append((slot, opts))

        response_list = self._send_rpc_batch_request('getBlock', request_list)
        for slot, response in zip(block_slot_list, response_list):
            if (not response) or ('result' not in response):
                block = SolanaBlockInfo(
                    slot=slot,
                    finalized=(commitment == FINALIZED),
                )
            else:
                net_block = response['result']
                block = SolanaBlockInfo(
                    slot=slot,
                    finalized=(commitment == FINALIZED),
                    hash='0x' + base58.b58decode(net_block['blockhash']).hex(),
                    parent_hash='0x' + base58.b58decode(net_block['previousBlockhash']).hex(),
                    time=net_block['blockTime'],
                    signs=net_block['signatures']
                )
            block_list.append(block)
        return block_list

    def get_recent_blockslot(self, commitment='confirmed') -> int:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getRecentBlockhash', opts)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        return blockhash_resp['result']['context']['slot']

    def get_recent_blockhash(self, commitment='confirmed') -> Blockhash:
        opts = {
            'commitment': commitment
        }
        blockhash_resp = self._send_rpc_request('getRecentBlockhash', opts)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        blockhash = blockhash_resp["result"]["value"]["blockhash"]
        return Blockhash(blockhash)

    def _fuzzing_transactions(self, signer: SolanaAccount, tx_list, tx_opts, request_list):
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

    def _send_multiple_transactions(self, signer: SolanaAccount, tx_list: [Transaction],
                                    skip_preflight: bool, preflight_commitment: str) -> [str]:
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
        return [SendResult(result=r.get('result'), error=r.get('error')) for r in response_list]

    def send_multiple_transactions(self, signer: SolanaAccount, tx_list: [], waiter,
                                   skip_preflight: bool, preflight_commitment: str) -> [{}]:
        send_result_list = self._send_multiple_transactions(signer, tx_list, skip_preflight, preflight_commitment)
        # Filter good transactions and wait the confirmations for them
        sign_list = [s.result for s in send_result_list if s.result]
        self._confirm_multiple_transactions(sign_list, waiter)
        # Get receipts for good transactions
        confirmed_list = self._get_multiple_receipts(sign_list)
        # Mix errors with receipts for good transactions
        receipt_list = []
        for s in send_result_list:
            if s.error:
                self.debug(f'Got error on preflight check of transaction: {s.error}')
                receipt_list.append(s.error)
            else:
                receipt_list.append(confirmed_list.pop(0))

        return receipt_list

    def _confirm_multiple_transactions(self, sign_list: [str], waiter=None):
        """Confirm a transaction."""
        if not len(sign_list):
            self.debug('No confirmations, because transaction list is empty')
            return

        base58_sign_list: List[str] = []
        for sign in sign_list:
            if isinstance(sign, str):
                base58_sign_list.append(b58encode(b58decode(sign)).decode("utf-8"))
            else:
                base58_sign_list.append(b58encode(sign).decode("utf-8"))

        opts = {
            "searchTransactionHistory": False
        }

        elapsed_time = 0
        while elapsed_time < CONFIRM_TIMEOUT:
            if elapsed_time > 0:
                time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY

            response = self._send_rpc_request("getSignatureStatuses", base58_sign_list, opts)
            result = response.get('result', None)
            if not result:
                continue

            if waiter:
                slot = result['context']['slot']
                waiter.on_wait_confirm(elapsed_time, slot)

            for status in result['value']:
                if not status:
                    break
                if status['confirmationStatus'] == 'processed':
                    break
            else:
                self.debug(f'Got confirmed status for transactions: {sign_list}')
                return

        self.warning(f'No confirmed status for transactions: {sign_list}')

    def _get_multiple_receipts(self, sign_list: [str]) -> [Any]:
        if not len(sign_list):
            return []
        opts = {"encoding": "json", "commitment": "confirmed"}
        request_list = [(sign, opts) for sign in sign_list]
        response_list = self._send_rpc_batch_request("getTransaction", request_list)
        return [r['result'] for r in response_list]


@logged_group("neon.Proxy")
class SolTxListSender:
    def __init__(self, sender, tx_list: [Transaction], name: str,
                 skip_preflight=SKIP_PREFLIGHT, preflight_commitment='confirmed'):
        self._s = sender
        self._name = name
        self._skip_preflight = skip_preflight
        self._preflight_commitment = preflight_commitment

        self._blockhash = None
        self._retry_idx = 0
        self._slots_behind = 0
        self._tx_list = tx_list
        self._node_behind_list = []
        self._bad_block_list = []
        self._blocked_account_list = []
        self._pending_list = []
        self._budget_exceeded_list = []
        self._storage_bad_status_list = []
        self._unknown_error_list = []

        self._all_tx_list = [self._node_behind_list,
                             self._bad_block_list,
                             self._blocked_account_list,
                             self._budget_exceeded_list,
                             self._pending_list]

    def clear(self):
        self._tx_list.clear()
        for lst in self._all_tx_list:
            lst.clear()

    def _get_full_list(self):
        return [tx for lst in self._all_tx_list for tx in lst]

    def send(self) -> SolTxListSender:
        solana = self._s.solana
        signer = self._s.signer
        waiter = self._s.waiter
        skip = self._skip_preflight
        commitment = self._preflight_commitment

        self.debug(f'start transactions sending: {self._name}')

        while (self._retry_idx < RETRY_ON_FAIL) and (len(self._tx_list)):
            self._retry_idx += 1
            self._slots_behind = 0

            receipt_list = solana.send_multiple_transactions(signer, self._tx_list, waiter, skip, commitment)
            self.update_transaction_cost(receipt_list)

            success_cnt = 0
            for receipt, tx in zip(receipt_list, self._tx_list):
                slots_behind = check_if_node_behind(receipt)
                if slots_behind:
                    self._slots_behind = slots_behind
                    self._node_behind_list.append(tx)
                elif check_if_blockhash_notfound(receipt):
                    self._bad_block_list.append(tx)
                elif check_if_accounts_blocked(receipt):
                    self._blocked_account_list.append(tx)
                elif check_for_errors(receipt):
                    if check_if_program_exceeded_instructions(receipt):
                        self._budget_exceeded_list.append(tx)
                    else:
                        custom = check_if_storage_is_empty_error(receipt)
                        if custom in (1, 4):
                            self._storage_bad_status_list.append(receipt)
                        else:
                            self._unknown_error_list.append(receipt)
                else:
                    success_cnt += 1
                    self._on_success_send(tx, receipt)

            self.debug(f'retry {self._retry_idx}, ' +
                       f'total receipts {len(receipt_list)}, ' +
                       f'success receipts {success_cnt}, ' +
                       f'node behind {len(self._node_behind_list)}, '
                       f'bad blocks {len(self._bad_block_list)}, ' +
                       f'blocked accounts {len(self._blocked_account_list)}, ' +
                       f'budget exceeded {len(self._budget_exceeded_list)}, ' +
                       f'bad storage: {len(self._storage_bad_status_list)}, ' +
                       f'unknown error: {len(self._unknown_error_list)}')

            self._on_post_send()

        if len(self._tx_list):
            raise RuntimeError('Run out of attempts to execute transaction')
        return self

    def update_transaction_cost(self, receipt_list):
        if not WRITE_TRANSACTION_COST_IN_DB:
            return False
        if not hasattr(self._s, 'eth_tx'):
            return False

        for receipt in receipt_list:
            update_transaction_cost(receipt, self._s.eth_tx, reason=self._name)

    def _on_success_send(self, tx: Transaction, receipt: {}) -> bool:
        """Store the last successfully blockhash and set it in _set_tx_blockhash"""
        self._blockhash = tx.recent_blockhash
        return False

    def _on_post_send(self):
        if len(self._unknown_error_list):
            raise SolTxError(self._unknown_error_list[0])
        elif len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            time.sleep(1)
        elif len(self._storage_bad_status_list):
            raise SolTxError(self._storage_bad_status_list[0])
        elif len(self._budget_exceeded_list):
            raise RuntimeError(COMPUTATION_BUDGET_EXCEEDED)

        # There is no more retries to send transactions
        if self._retry_idx >= RETRY_ON_FAIL:
            if not self._is_canceled:
                self._cancel()
            return

        if len(self._blocked_account_list):
            time.sleep(0.4)  # one block time

        # force changing of recent_blockhash if Solana doesn't accept the current one
        if len(self._bad_block_list):
            self._blockhash = None

        # resend not-accepted transactions
        self._move_txlist()

    def _set_tx_blockhash(self, tx):
        """Try to keep the branch of block history"""
        tx.recent_blockhash = self._blockhash
        tx.signatures.clear()

    def _move_txlist(self):
        full_list = self._get_full_list()
        self.clear()
        for tx in full_list:
            self._set_tx_blockhash(tx)
            self._tx_list.append(tx)
        if len(self._tx_list):
            self.debug(f' Resend Solana transactions: {len(self._tx_list)}')


@logged_group("neon.Proxy")
class Measurements:
    def __init__(self):
        pass

    # Do not change headers in info logs! This name used in CI measurements (see function `cleanup_docker` in
    # .buildkite/steps/deploy-test.sh)
    def extract(self, reason: str, receipt: {}):
        if not LOG_SENDING_SOLANA_TRANSACTION:
            return

        try:
            self.debug(f"send multiple transactions for reason {reason}")

            measurements = self._extract_measurements_from_receipt(receipt)
            for m in measurements:
                self.info(f'get_measurements: {json.dumps(m)}')
        except Exception as err:
            self.error(f"get_measurements: can't get measurements {err}")
            self.info(f"get measurements: failed result {json.dumps(receipt, indent=3)}")

    def _extract_measurements_from_receipt(self, receipt):
        if check_for_errors(receipt):
            self.warning("Can't get measurements from receipt with error")
            self.info(f"Failed result: {json.dumps(receipt, indent=3)}")
            return []

        log_messages = receipt['meta']['logMessages']
        transaction = receipt['transaction']
        accounts = transaction['message']['accountKeys']
        instructions = []
        for instr in transaction['message']['instructions']:
            program = accounts[instr['programIdIndex']]
            instructions.append({
                'accs': [accounts[acc] for acc in instr['accounts']],
                'program': accounts[instr['programIdIndex']],
                'data': base58.b58decode(instr['data']).hex()
            })

        pattern = re.compile('Program ([0-9A-Za-z]+) (.*)')
        messages = []
        for log in log_messages:
            res = pattern.match(log)
            if res:
                (program, reason) = res.groups()
                if reason == 'invoke [1]': messages.append({'program': program, 'logs': []})
            messages[-1]['logs'].append(log)

        for instr in instructions:
            if instr['program'] in ('KeccakSecp256k11111111111111111111111111111',): continue
            if messages[0]['program'] != instr['program']:
                raise ValueError('Invalid program in log messages: expect %s, actual %s' % (
                    messages[0]['program'], instr['program']))
            instr['logs'] = messages.pop(0)['logs']
            exit_result = re.match(r'Program %s (success)' % instr['program'], instr['logs'][-1])
            if not exit_result: raise ValueError("Can't get exit result")
            instr['result'] = exit_result.group(1)

            if instr['program'] == EVM_LOADER_ID:
                memory_result = re.match(r'Program log: Total memory occupied: ([0-9]+)', instr['logs'][-3])
                instruction_result = re.match(
                    r'Program %s consumed ([0-9]+) of ([0-9]+) compute units' % instr['program'], instr['logs'][-2])
                if not (memory_result and instruction_result):
                    raise ValueError("Can't parse measurements for evm_loader")
                instr['measurements'] = {
                    'instructions': instruction_result.group(1),
                    'memory': memory_result.group(1)
                }

        result = []
        for instr in instructions:
            if instr['program'] == EVM_LOADER_ID:
                result.append({
                    'program': instr['program'],
                    'measurements': instr['measurements'],
                    'result': instr['result'],
                    'data': instr['data']
                })
        return result


def get_error_definition_from_receipt(receipt):
    err_from_receipt = get_from_dict(receipt, 'result', 'meta', 'err', 'InstructionError')
    if err_from_receipt is not None:
        return err_from_receipt

    err_from_receipt_result = get_from_dict(receipt, 'meta', 'err', 'InstructionError')
    if err_from_receipt_result is not None:
        return err_from_receipt_result

    err_from_send_trx_error = get_from_dict(receipt, 'data', 'err', 'InstructionError')
    if err_from_send_trx_error is not None:
        return err_from_send_trx_error

    err_from_send_trx_error = get_from_dict(receipt, 'data', 'err')
    if err_from_send_trx_error is not None:
        return err_from_send_trx_error

    err_from_prepared_receipt = get_from_dict(receipt, 'err', 'InstructionError')
    if err_from_prepared_receipt is not None:
        return err_from_prepared_receipt

    return None


def check_for_errors(receipt):
    if get_error_definition_from_receipt(receipt) is not None:
        return True
    return False


def check_if_big_transaction(err: Exception) -> bool:
    return str(err).startswith("transaction too large:")


PROGRAM_FAILED_TO_COMPLETE = 'ProgramFailedToComplete'
COMPUTATION_BUDGET_EXCEEDED = 'ComputationalBudgetExceeded'


def check_if_program_exceeded_instructions(receipt):
    error_type = None
    if isinstance(receipt, Exception):
        error_type = str(receipt)
    else:
        error_arr = get_error_definition_from_receipt(receipt)
        if isinstance(error_arr, list):
            error_type = error_arr[1]

    if isinstance(error_type, str):
        return error_type in [PROGRAM_FAILED_TO_COMPLETE, COMPUTATION_BUDGET_EXCEEDED]
    return False


def check_if_storage_is_empty_error(receipt):
    error_arr = get_error_definition_from_receipt(receipt)
    if error_arr is not None and isinstance(error_arr, list):
        error_dict = error_arr[1]
        if isinstance(error_dict, dict) and 'Custom' in error_dict:
            custom = error_dict['Custom']
            if custom in (1, 4):
                return custom
    return 0


def get_logs_from_receipt(receipt):
    log_from_receipt = get_from_dict(receipt, 'result', 'meta', 'logMessages')
    if log_from_receipt is not None:
        return log_from_receipt

    log_from_receipt_result = get_from_dict(receipt, 'meta', 'logMessages')
    if log_from_receipt_result is not None:
        return log_from_receipt_result

    log_from_receipt_result_meta = get_from_dict(receipt, 'logMessages')
    if log_from_receipt_result_meta is not None:
        return log_from_receipt_result_meta

    log_from_send_trx_error = get_from_dict(receipt, 'data', 'logs')
    if log_from_send_trx_error is not None:
        return log_from_send_trx_error

    log_from_prepared_receipt = get_from_dict(receipt, 'logs')
    if log_from_prepared_receipt is not None:
        return log_from_prepared_receipt

    return []


@logged_group("neon.Proxy")
def check_if_accounts_blocked(receipt, *, logger):
    logs = get_logs_from_receipt(receipt)
    if logs is None:
        logger.error("Can't get logs")
        logger.info(f"Failed result: {json.dumps(receipt, indent=3)}")
        return False

    ro_blocked = "trying to execute transaction on ro locked account"
    rw_blocked = "trying to execute transaction on rw locked account"
    for log in logs:
        if log.find(ro_blocked) >= 0 or log.find(rw_blocked) >= 0:
            return True
    return False


def check_if_blockhash_notfound(receipt):
    return (not receipt) or (get_from_dict(receipt, 'data', 'err') == 'BlockhashNotFound')


def check_if_node_behind(receipt):
    return get_from_dict(receipt, 'data', 'numSlotsBehind')
