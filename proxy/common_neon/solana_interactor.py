import base58
import base64
import json
import logging
import re
import time
import requests

from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.api import SendTransactionError
from solana.rpc.commitment import Confirmed
from solana.rpc.types import RPCResponse, TxOpts
from solana.transaction import Transaction
from urllib.parse import urlparse
from itertools import zip_longest

from .costs import update_transaction_cost
from .utils import get_from_dict
from ..environment import EVM_LOADER_ID, CONFIRMATION_CHECK_DELAY, LOG_SENDING_SOLANA_TRANSACTION, RETRY_ON_FAIL

from typing import Any, List, NamedTuple, Union, cast

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class AccountInfo(NamedTuple):
    tag: int
    lamports: int
    owner: PublicKey

class SolanaInteractor:
    def __init__(self, signer, client: SolanaClient) -> None:
        self.signer = signer
        self.client = client

    def _send_rpc_batch_request(self, method: str, params_list: List[Any]) -> List[RPCResponse]:
        request_data = []
        for params in params_list:
            request_id = next(self.client._provider._request_counter) + 1
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            request_data.append(request)

        response = self.client._provider.session.post(self.client._provider.endpoint_uri, headers={"Content-Type": "application/json"}, json=request_data)
        response.raise_for_status()

        response_data = cast(List[RPCResponse], response.json())
        response_data.sort(key=lambda r: r["id"])

        for request, response in zip_longest(request_data, response_data):
            if request["id"] != response["id"]:
                raise Exception("Invalid RPC response: request {} response {}", request, response)

        return response_data

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
        logger.debug("\n{}".format(json.dumps(result, indent=4, sort_keys=True)))

        info = result['result']['value']
        if info is None:
            logger.debug("Can't get information about {}".format(storage_account))
            return None

        data = base64.b64decode(info['data'][0])

        account_tag = data[0]
        lamports = info['lamports']
        owner = info['owner']

        return AccountInfo(account_tag, lamports, owner)

    def get_multiple_accounts_info(self, accounts: List[PublicKey]) -> List[AccountInfo]:
        options = {
            "encoding": "base64",
            "commitment": "confirmed",
            "dataSlice": { "offset": 0, "length": 16 }
        }
        result = self.client._provider.make_request("getMultipleAccounts", list(map(str, accounts)), options)
        logger.debug("\n{}".format(json.dumps(result, indent=4, sort_keys=True)))

        if result['result']['value'] is None:
            logger.debug("Can't get information about {}".format(accounts))
            return None

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


    def get_multiple_rent_exempt_balances_for_size(self, size_list: List[int]) -> List[int]:
        request = map(lambda size: (size, {"commitment": "confirmed"}), size_list)
        response = self._send_rpc_batch_request("getMinimumBalanceForRentExemption", request)
        return list(map(lambda r: r["result"], response))


    def _getAccountData(self, account, expected_length, owner=None):
        info = self.client.get_account_info(account, commitment=Confirmed)['result']['value']
        if info is None:
            raise Exception("Can't get information about {}".format(account))

        data = base64.b64decode(info['data'][0])
        if len(data) < expected_length:
            raise Exception("Wrong data length for account data {}".format(account))
        return data


    def send_transaction(self, trx, eth_trx, reason=None):
        for _i in range(RETRY_ON_FAIL):
            reciept = self.send_transaction_unconfirmed(trx)
            result = self.collect_result(reciept, eth_trx, reason)
            if result is not None:
                return result
            time.sleep(0.1)
        RuntimeError("Failed {} times to send transaction or get confirmnation {}".format(RETRY_ON_FAIL, trx.__dict__))


    def send_transaction_unconfirmed(self, txn: Transaction):
        for _i in range(RETRY_ON_FAIL):
            # TODO: Cache recent blockhash
            blockhash_resp = self.client.get_recent_blockhash(commitment=Confirmed)
            if not blockhash_resp["result"]:
                raise RuntimeError("failed to get recent blockhash")
            blockhash = blockhash_resp["result"]["value"]["blockhash"]
            txn.recent_blockhash = Blockhash(blockhash)
            txn.sign(self.signer)
            try:
                return self.client.send_raw_transaction(txn.serialize(), opts=TxOpts(skip_preflight=True, preflight_commitment=Confirmed))["result"]
            except SendTransactionError as err:
                err_type = get_from_dict(err.result, "data", "err")
                if err_type is not None and isinstance(err_type, str) and err_type == "BlockhashNotFound":
                    logger.debug("BlockhashNotFound {}".format(blockhash))
                    time.sleep(0.1)
                    continue
                raise
        raise RuntimeError("Failed trying {} times to get Blockhash for transaction {}".format(RETRY_ON_FAIL, txn.__dict__))

    def send_multiple_transactions_unconfirmed(self, transactions: List[Transaction], skip_preflight: bool = True) -> List[str]:
        blockhash_resp = self.client.get_recent_blockhash(commitment=Confirmed)
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")

        blockhash = blockhash_resp["result"]["value"]["blockhash"]

        request = []
        for transaction in transactions:
            transaction.recent_blockhash = blockhash
            transaction.sign(self.signer)
            base64_transaction = base64.b64encode(transaction.serialize()).decode("utf-8")
            request.append((base64_transaction, {"skipPreflight": skip_preflight, "encoding": "base64", "preflightCommitment": "confirmed"}))

        response = self._send_rpc_batch_request("sendTransaction", request)
        return list(map(lambda r: r["result"], response))

    def send_measured_transaction(self, trx, eth_trx, reason):
        if LOG_SENDING_SOLANA_TRANSACTION:
            logger.debug("send_measured_transaction for reason %s: %s ", reason, trx.__dict__)
        result = self.send_transaction(trx, eth_trx, reason=reason)
        self.get_measurements(result)
        return result

    # Do not rename this function! This name used in CI measurements (see function `cleanup_docker` in
    # .buildkite/steps/deploy-test.sh)
    def get_measurements(self, result):
        try:
            measurements = self.extract_measurements_from_receipt(result)
            for m in measurements: logger.info(json.dumps(m))
        except Exception as err:
            logger.error("Can't get measurements %s"%err)
            logger.info("Failed result: %s"%json.dumps(result, indent=3))

    def confirm_multiple_transactions(self, signatures: List[Union[str, bytes]]):
        """Confirm a transaction."""
        # TODO should be set as predefined constant
        TIMEOUT = 10  # 30 seconds  pylint: disable=invalid-name
        elapsed_time = 0
        while elapsed_time < TIMEOUT:
            response = self.client.get_signature_statuses(signatures)
            logger.debug('confirm_transactions: %s', response)
            if response['result'] is None:
                continue

            for status in response['result']['value']:
                if status is None:
                    break
                if status['confirmationStatus'] == 'processed':
                    break
            else:
                return

            time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY

    def get_multiple_confirmed_transactions(self, signatures: List[str]) -> List[Any]:
        request = map(lambda signature: (signature, {"encoding": "json", "commitment": "confirmed"}), signatures)
        response = self._send_rpc_batch_request("getTransaction", request)
        return list(map(lambda r: r["result"], response))

    def collect_results(self, receipts: List[str], eth_trx: Any = None, reason: str = None) -> List[Any]:
        self.confirm_multiple_transactions(receipts)
        transactions = self.get_multiple_confirmed_transactions(receipts)

        for transaction in transactions:
            update_transaction_cost(transaction, eth_trx, reason)

        return transactions

    def collect_result(self, reciept, eth_trx, reason=None):
        self.confirm_multiple_transactions([reciept])
        result = self.client.get_confirmed_transaction(reciept)['result']
        update_transaction_cost(result, eth_trx, reason)
        return result

    @staticmethod
    def extract_measurements_from_receipt(receipt):
        if check_for_errors(receipt):
            logger.warning("Can't get measurements from receipt with error")
            logger.info("Failed result: %s"%json.dumps(receipt, indent=3))
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
                raise Exception('Invalid program in log messages: expect %s, actual %s' % (messages[0]['program'], instr['program']))
            instr['logs'] = messages.pop(0)['logs']
            exit_result = re.match(r'Program %s (success)'%instr['program'], instr['logs'][-1])
            if not exit_result: raise Exception("Can't get exit result")
            instr['result'] = exit_result.group(1)

            if instr['program'] == EVM_LOADER_ID:
                memory_result = re.match(r'Program log: Total memory occupied: ([0-9]+)', instr['logs'][-3])
                instruction_result = re.match(r'Program %s consumed ([0-9]+) of ([0-9]+) compute units'%instr['program'], instr['logs'][-2])
                if not (memory_result and instruction_result):
                    raise Exception("Can't parse measurements for evm_loader")
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


def get_error_definition_from_reciept(receipt):
    err_from_reciept = get_from_dict(receipt, 'result', 'meta', 'err', 'InstructionError')
    if err_from_reciept is not None:
        return err_from_reciept

    err_from_reciept_result = get_from_dict(receipt, 'meta', 'err', 'InstructionError')
    if err_from_reciept_result is not None:
        return err_from_reciept_result

    err_from_send_trx_error = get_from_dict(receipt, 'data', 'err', 'InstructionError')
    if err_from_send_trx_error is not None:
        return err_from_send_trx_error

    err_from_prepared_receipt = get_from_dict(receipt, 'err', 'InstructionError')
    if err_from_prepared_receipt is not None:
        return err_from_prepared_receipt

    return None



def check_for_errors(receipt):
    if get_error_definition_from_reciept(receipt) is not None:
        return True
    return False


def check_if_program_exceeded_instructions(receipt):
    error_arr = get_error_definition_from_reciept(receipt)
    if error_arr is not None and isinstance(error_arr, list):
        error_type = error_arr[1]
        if isinstance(error_type, str):
            if error_type == 'ProgramFailedToComplete':
                return True
            if error_type == 'ComputationalBudgetExceeded':
                return True
    return False


def check_if_storage_is_empty_error(receipt):
    error_arr = get_error_definition_from_reciept(receipt)
    if error_arr is not None and isinstance(error_arr, list):
        error_dict = error_arr[1]
        if isinstance(error_dict, dict) and 'Custom' in error_dict:
            if error_dict['Custom'] == 1 or error_dict['Custom'] == 4:
                return True
    return False


def get_logs_from_reciept(receipt):
    log_from_reciept = get_from_dict(receipt, 'result', 'meta', 'logMessages')
    if log_from_reciept is not None:
        return log_from_reciept

    log_from_reciept_result = get_from_dict(receipt, 'meta', 'logMessages')
    if log_from_reciept_result is not None:
        return log_from_reciept_result

    log_from_reciept_result_meta = get_from_dict(receipt, 'logMessages')
    if log_from_reciept_result_meta is not None:
        return log_from_reciept_result_meta

    log_from_send_trx_error = get_from_dict(receipt, 'data', 'logs')
    if log_from_send_trx_error is not None:
        return log_from_send_trx_error

    log_from_prepared_receipt = get_from_dict(receipt, 'logs')
    if log_from_prepared_receipt is not None:
        return log_from_prepared_receipt

    return None


def check_if_accounts_blocked(receipt):
    logs = get_logs_from_reciept(receipt)
    if logs is None:
        logger.error("Can't get logs")
        logger.info("Failed result: %s"%json.dumps(receipt, indent=3))

    ro_blocked = "trying to execute transaction on ro locked account"
    rw_blocked = "trying to execute transaction on rw locked account"
    for log in logs:
        if log.find(ro_blocked) >= 0 or log.find(rw_blocked) >= 0:
            return True
    return False
