import base58
import base64
import json
import logging
import re
import time

from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts

from .costs import update_transaction_cost
from .utils import get_from_dict
from ..environment import EVM_LOADER_ID, CONFIRMATION_CHECK_DELAY, LOG_SENDING_SOLANA_TRANSACTION

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class SolanaInteractor:
    def __init__(self, signer, client: SolanaClient) -> None:
        self.signer = signer
        self.client = client


    def get_operator_key(self):
        return self.signer.public_key()


    def get_account_info(self, storage_account):
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

        return (account_tag, lamports, owner)


    def get_sol_balance(self, account):
        return self.client.get_balance(account, commitment=Confirmed)['result']['value']


    def get_rent_exempt_balance_for_size(self, size):
        return self.client.get_minimum_balance_for_rent_exemption(size, commitment=Confirmed)["result"]


    def _getAccountData(self, account, expected_length, owner=None):
        info = self.client.get_account_info(account, commitment=Confirmed)['result']['value']
        if info is None:
            raise Exception("Can't get information about {}".format(account))

        data = base64.b64decode(info['data'][0])
        if len(data) < expected_length:
            raise Exception("Wrong data length for account data {}".format(account))
        return data


    def send_transaction(self, trx, eth_trx, reason=None):
        reciept = self.send_transaction_unconfirmed(trx)
        result = self.collect_result(reciept, eth_trx, reason)
        return result


    def send_transaction_unconfirmed(self, trx):
        result = self.client.send_transaction(trx, self.signer, opts=TxOpts(preflight_commitment=Confirmed))["result"]
        return result

    def collect_result(self, reciept, eth_trx, reason=None):
        self.confirm_transaction(reciept)
        result = self.client.get_confirmed_transaction(reciept)
        update_transaction_cost(result, eth_trx, reason)
        return result

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


    def confirm_transaction(self, tx_sig, confirmations=0):
        """Confirm a transaction."""
        TIMEOUT = 30  # 30 seconds  pylint: disable=invalid-name
        elapsed_time = 0
        while elapsed_time < TIMEOUT:
            logger.debug('confirm_transaction for %s', tx_sig)
            resp = self.client.get_signature_statuses([tx_sig])
            logger.debug('confirm_transaction: %s', resp)
            if resp["result"]:
                status = resp['result']['value'][0]
                if status and (status['confirmationStatus'] == 'finalized' or \
                status['confirmationStatus'] == 'confirmed' and status['confirmations'] >= confirmations):
                    return
            time.sleep(CONFIRMATION_CHECK_DELAY)
            elapsed_time += CONFIRMATION_CHECK_DELAY
        raise RuntimeError("could not confirm transaction: ", tx_sig)


    def collect_results(self, receipts, eth_trx=None, reason=None):
        results = []
        for rcpt in receipts:
            results.append(self.collect_result(rcpt, eth_trx, reason))
        return results

    @staticmethod
    def extract_measurements_from_receipt(receipt):
        if check_for_errors(receipt):
            logger.warning("Can't get measurements from receipt with error")
            logger.info("Failed result: %s"%json.dumps(receipt, indent=3))
            return []

        log_messages = receipt['result']['meta']['logMessages']
        transaction = receipt['result']['transaction']
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


def check_if_continue_returned(result):
    tx_info = result['result']
    accounts = tx_info["transaction"]["message"]["accountKeys"]
    evm_loader_instructions = []

    for idx, instruction in enumerate(tx_info["transaction"]["message"]["instructions"]):
        if accounts[instruction["programIdIndex"]] == EVM_LOADER_ID:
            evm_loader_instructions.append(idx)

    for inner in (tx_info['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                    instruction = base58.b58decode(event['data'])[:1]
                    if int().from_bytes(instruction, "little") == 6:  # OnReturn evmInstruction code
                        return tx_info['transaction']['signatures'][0]

    return None
