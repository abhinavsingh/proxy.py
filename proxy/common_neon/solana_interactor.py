import base58
import base64
import json
import re
import time

from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import RPCResponse
from solana.transaction import Transaction
from itertools import zip_longest
from logged_groups import logged_group

from .costs import update_transaction_cost
from .utils import get_from_dict
from ..environment import EVM_LOADER_ID, CONFIRMATION_CHECK_DELAY, WRITE_TRANSACTION_COST_IN_DB
from ..environment import LOG_SENDING_SOLANA_TRANSACTION, FUZZING_BLOCKHASH, CONFIRM_TIMEOUT

from typing import Any, List, NamedTuple, cast


class AccountInfo(NamedTuple):
    tag: int
    lamports: int
    owner: PublicKey


@logged_group("neon.Proxy")
class SolanaInteractor:
    def __init__(self, signer, client: SolanaClient) -> None:
        self.signer = signer
        self.client = client
        self._fuzzing_hash_cycle = False

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        full_request_data = []
        full_response_data = []
        request_data = []
        client = self.client._provider
        headers = {"Content-Type": "application/json"}

        for params in params_list:
            request_id = next(client._request_counter) + 1
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            request_data.append(request)
            full_request_data.append(request)

            # Protection from big payload
            if len(request_data) == 30 or len(full_request_data) == len(params_list):
                response = client.session.post(client.endpoint_uri, headers=headers, json=request_data)
                response.raise_for_status()

                response_data = cast(List[RPCResponse], response.json())

                full_response_data += response_data
                request_data.clear()

        full_response_data.sort(key=lambda r: r["id"])

        for request, response in zip_longest(full_request_data, full_response_data):
            # self.debug(f'Request: {request}')
            # self.debug(f'Response: {response}')
            if request["id"] != response["id"]:
                raise RuntimeError(f"Invalid RPC response: request {request} response {response}")

        return full_response_data

    def get_operator_key(self):
        return self.signer.public_key()

    def get_account_info(self, storage_account) -> AccountInfo:
        opts = {
            "encoding": "base64",
            "commitment": "confirmed",
            "dataSlice": {
                "offset": 0,
                "length": 16,
            }
        }

        result = self.client._provider.make_request("getAccountInfo", str(storage_account), opts)
        self.debug(f"\n{json.dumps(result, indent=4, sort_keys=True)}")

        info = result['result']['value']
        if info is None:
            self.debug(f"Can't get information about {storage_account}")
            return None

        data = base64.b64decode(info['data'][0])

        account_tag = data[0]
        lamports = info['lamports']
        owner = info['owner']

        return AccountInfo(account_tag, lamports, owner)

    def get_multiple_accounts_info(self, accounts: [PublicKey]) -> [AccountInfo]:
        options = {
            "encoding": "base64",
            "commitment": "confirmed",
            "dataSlice": { "offset": 0, "length": 16 }
        }
        result = self.client._provider.make_request("getMultipleAccounts", [str(a) for a in accounts], options)
        self.debug(f"\n{json.dumps(result, indent=4, sort_keys=True)}")

        if result['result']['value'] is None:
            self.debug(f"Can't get information about {accounts}")
            return []

        accounts_info = []
        for info in result['result']['value']:
            if info is None:
                accounts_info.append(None)
            else:
                data = base64.b64decode(info['data'][0])
                accounts_info.append(AccountInfo(tag=data[0], lamports=info['lamports'], owner=info['owner']))

        return accounts_info

    def get_sol_balance(self, account):
        return self.client.get_balance(account, commitment=Confirmed)['result']['value']

    def get_multiple_rent_exempt_balances_for_size(self, size_list: [int]) -> [int]:
        opts = {"commitment": "confirmed"}
        request_list = [(size, opts) for size in size_list]
        response_list = self._send_rpc_batch_request("getMinimumBalanceForRentExemption", request_list)
        return [r['result'] for r in response_list]

    def _getAccountData(self, account, expected_length):
        info = self.client.get_account_info(account, commitment=Confirmed)['result']['value']
        if info is None:
            raise ValueError(f"Can't get information about {account}")

        data = base64.b64decode(info['data'][0])
        if len(data) < expected_length:
            raise ValueError(f"Wrong data length for account data {account}")
        return data

    def get_recent_blockslot(self) -> int:
        blockhash_resp = self.client.get_recent_blockhash(commitment=Confirmed)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        return blockhash_resp['result']['context']['slot']

    def get_recent_blockhash(self) -> Blockhash:
        blockhash_resp = self.client.get_recent_blockhash(commitment=Confirmed)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        blockhash = blockhash_resp["result"]["value"]["blockhash"]

        if not FUZZING_BLOCKHASH:
            return Blockhash(blockhash)

        slot = blockhash_resp['result']['context']['slot']
        self._fuzzing_hash_cycle = not self._fuzzing_hash_cycle
        if not self._fuzzing_hash_cycle:
            self.debug(f"good block {blockhash} for the slot {slot}")
            return Blockhash(blockhash)

        # blockhash = '4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4'
        opts = {
            "encoding": "json",
            "transactionDetails": "none",
            "rewards": False
        }
        block = self.client._provider.make_request("getBlock", slot - 500, opts)
        blockhash = block['result']['blockhash']
        self.debug(f"fuzzing block {blockhash} for slot {slot}")
        return Blockhash(blockhash)

    def sign_transaction(self, tx: Transaction):
        tx.sign(self.signer)

    def send_multiple_transactions_unconfirmed(self, tx_list: [Transaction], skip_preflight=True) -> [str]:
        opts = {
            "skipPreflight": skip_preflight,
            "encoding": "base64",
            "preflightCommitment": "confirmed"
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
                self.sign_transaction(tx)
            base64_tx = base64.b64encode(tx.serialize()).decode('utf-8')
            request_list.append((base64_tx, opts))

        response_list = self._send_rpc_batch_request('sendTransaction', request_list)
        return [r['result'] for r in response_list]

    def send_multiple_transactions(self, tx_list, eth_tx, reason, waiter=None, skip_preflight=True) -> [{}]:
        debug_measurements = LOG_SENDING_SOLANA_TRANSACTION and (reason in ['CancelWithNonce', 'CallFromRawEthereumTX'])

        if debug_measurements:
            self.debug(f"send multiple transactions for reason {reason}: {eth_tx.__dict__}")

        sign_list = self.send_multiple_transactions_unconfirmed(tx_list, skip_preflight=skip_preflight)
        self.confirm_multiple_transactions(sign_list, waiter)
        receipt_list = self.get_multiple_confirmed_transactions(sign_list)

        if WRITE_TRANSACTION_COST_IN_DB:
            for receipt in receipt_list:
                update_transaction_cost(receipt, eth_tx, reason)

        if debug_measurements:
            for receipt in receipt_list:
                if receipt is not None:
                    self.get_measurements(receipt)

        return receipt_list

    def send_transaction(self, trx, eth_tx, reason=None):
        return self.send_multiple_transactions([trx], eth_tx, reason)[0]

    # Do not rename this function! This name used in CI measurements (see function `cleanup_docker` in
    # .buildkite/steps/deploy-test.sh)
    def get_measurements(self, receipt):
        try:
            measurements = self.extract_measurements_from_receipt(receipt)
            for m in measurements:
                self.info(f'get_measurements: {json.dumps(m)}')
        except Exception as err:
            self.error(f"get_measurements: can't get measurements {err}")
            self.info(f"get measurements: failed result {json.dumps(receipt, indent=3)}")

    def confirm_multiple_transactions(self, sign_list: [str], waiter=None):
        """Confirm a transaction."""
        elapsed_time = 0
        while elapsed_time < CONFIRM_TIMEOUT:
            if waiter:
                waiter.on_wait_confirm(elapsed_time)

            response = self.client.get_signature_statuses(sign_list)
            result = response['result']
            if not result:
                continue

            for status in result['value']:
                if not status:
                    break
                if status['confirmationStatus'] == 'processed':
                    break
            else:
                self.debug(f'Got confirmed status for transactions: {sign_list}')
                return

            time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY
        self.warning(f'No confirmed status for transactions: {sign_list}')

    def get_multiple_confirmed_transactions(self, sign_list: [str]) -> [Any]:
        opts = {"encoding": "json", "commitment": "confirmed"}
        request_list = [(sign, opts) for sign in sign_list]
        response_list = self._send_rpc_batch_request("getTransaction", request_list)
        return [r['result'] for r in response_list]

    def extract_measurements_from_receipt(self, receipt):
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
                if reason == 'invoke [1]': messages.append({'program':program,'logs':[]})
            messages[-1]['logs'].append(log)

        for instr in instructions:
            if instr['program'] in ('KeccakSecp256k11111111111111111111111111111',): continue
            if messages[0]['program'] != instr['program']:
                raise ValueError('Invalid program in log messages: expect %s, actual %s' % (messages[0]['program'], instr['program']))
            instr['logs'] = messages.pop(0)['logs']
            exit_result = re.match(r'Program %s (success)'%instr['program'], instr['logs'][-1])
            if not exit_result: raise ValueError("Can't get exit result")
            instr['result'] = exit_result.group(1)

            if instr['program'] == EVM_LOADER_ID:
                memory_result = re.match(r'Program log: Total memory occupied: ([0-9]+)', instr['logs'][-3])
                instruction_result = re.match(r'Program %s consumed ([0-9]+) of ([0-9]+) compute units'%instr['program'], instr['logs'][-2])
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
                        'program':instr['program'],
                        'measurements':instr['measurements'],
                        'result':instr['result'],
                        'data':instr['data']
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
            if error_dict['Custom'] == 1 or error_dict['Custom'] == 4:
                return True
    return False


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

    return None


@logged_group("neon.Proxy")
def check_if_accounts_blocked(receipt, *, logger):
    logs = get_logs_from_receipt(receipt)
    if logs is None:
        logger.error("Can't get logs")
        logger.info("Failed result: %s"%json.dumps(receipt, indent=3))

    ro_blocked = "trying to execute transaction on ro locked account"
    rw_blocked = "trying to execute transaction on rw locked account"
    for log in logs:
        if log.find(ro_blocked) >= 0 or log.find(rw_blocked) >= 0:
            return True
    return False
