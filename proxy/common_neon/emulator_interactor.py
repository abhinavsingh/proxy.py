import json
import subprocess
from logged_groups import logged_group

from typing import Optional, Dict, Any
from ..common_neon.eth_proto import Trx as NeonTrx

from ..common_neon.elf_params import ElfParams

from .environment_utils import neon_cli
from .errors import EthereumError
from .types import NeonEmulatingResult


@logged_group("neon.Proxy")
def call_emulated(contract_id, caller_id, data=None, value=None, *, logger) -> NeonEmulatingResult:
    output = emulator(contract_id, caller_id, data, value)
    logger.debug(f"Call emulated. contract_id: {contract_id}, caller_id: {caller_id}, data: {data}, value: {value}, return: {output}")
    result = json.loads(output)
    check_emulated_exit_status(result)
    return result


@logged_group("neon.Proxy")
def call_trx_emulated(neon_trx: NeonTrx, *, logger) -> NeonEmulatingResult:
    neon_sender_acc = neon_trx.sender()
    contract = neon_trx.contract()
    logger.debug(f'sender address: 0x{neon_sender_acc}')
    if contract:
        dst = 'deploy'
        logger.debug(f'deploy contract: {contract}')
    else:
        dst = neon_trx.toAddress.hex()
        logger.debug(f'destination address {dst}')
    logger.debug(f"Calling data: {(dst, neon_sender_acc, neon_trx.callData.hex(), hex(neon_trx.value))}")
    emulator_json = call_emulated(dst, neon_sender_acc, neon_trx.callData.hex(), hex(neon_trx.value))
    logger.debug(f'emulator returns: {json.dumps(emulator_json, sort_keys=True)}')
    return emulator_json


@logged_group("neon.Proxy")
def check_emulated_exit_status(result: Dict[str, Any], *, logger):
    exit_status = result['exit_status']
    if exit_status == 'revert':
        revert_data = result.get('result')
        logger.debug(f"Got revert call emulated result with data: {revert_data}")
        result_value = decode_revert_message(revert_data)
        if result_value is None:
            raise EthereumError(code=3, message='execution reverted', data='0x' + revert_data)
        else:
            raise EthereumError(code=3, message='execution reverted: ' + result_value, data='0x' + revert_data)

    if exit_status != "succeed":
        logger.debug(f"Got not succeed emulate exit_status: {exit_status}")
        reason = result.get('exit_reason')
        if isinstance(reason, str):
            raise EthereumError(code=3, message=f'execution finished with error: {reason}')
        elif isinstance(reason, dict):
            error = None
            if 'Error' in reason:
                error = decode_error_message(reason.get('Error'))
            if (not error) and ('Fatal' in reason):
                error = decode_fatal_message(reason.get('Fatal'))
            if error:
                raise EthereumError(code=3, message=f'execution finished with error: {str(error)}')
        raise EthereumError(code=3, message=exit_status)


def decode_error_message(reason: str) -> Optional[str]:
    ERROR_DICT = {
        'StackUnderflow': 'trying to pop from an empty stack',
        'StackOverflow': 'trying to push into a stack over stack limit',
        'InvalidJump': 'jump destination is invalid',
        'InvalidRange': 'an opcode accesses memory region, but the region is invalid',
        'DesignatedInvalid': 'encountered the designated invalid opcode',
        'CallTooDeep': 'call stack is too deep (runtime)',
        'CreateCollision': 'create opcode encountered collision (runtime)',
        'CreateContractLimit': 'create init code exceeds limit (runtime)',
        'OutOfOffset': 'an opcode accesses external information, but the request is off offset limit (runtime)',
        'OutOfGas': 'execution runs out of gas (runtime)',
        'OutOfFund': 'not enough fund to start the execution (runtime)',
        'PCUnderflow': 'PC underflow (unused)',
        'CreateEmpty': 'attempt to create an empty account (runtime, unused)',
        'StaticModeViolation': 'STATICCALL tried to change state',
    }
    return ERROR_DICT.get(reason)


def decode_fatal_message(reason: str) -> Optional[str]:
    FATAL_DICT = {
        'NotSupported': 'the operation is not supported',
        'UnhandledInterrupt': 'the trap (interrupt) is unhandled',
        'CallErrorAsFatal': 'the environment explicitly set call errors as fatal error'
    }
    return FATAL_DICT.get(reason)


@logged_group("neon.Proxy")
def decode_revert_message(data: str, *, logger) -> Optional[str]:
    data_len = len(data)
    if data_len == 0:
        return None

    if data_len < 8:
        raise Exception(f"Too less bytes to decode revert signature: {data_len}, data: 0x{data}")

    if data[:8] == '4e487b71':  # keccak256("Panic(uint256)")
        return None

    if data[:8] != '08c379a0':  # keccak256("Error(string)")
        logger.debug(f"Failed to decode revert_message, unknown revert signature: {data[:8]}")
        return None

    if data_len < 8 + 64:
        raise Exception(f"Too less bytes to decode revert msg offset: {data_len}, data: 0x{data}")
    offset = int(data[8:8 + 64], 16) * 2

    if data_len < 8 + offset + 64:
        raise Exception(f"Too less bytes to decode revert msg len: {data_len}, data: 0x{data}")
    length = int(data[8 + offset:8 + offset + 64], 16) * 2

    if data_len < 8 + offset + 64 + length:
        raise Exception(f"Too less bytes to decode revert msg: {data_len}, data: 0x{data}")

    message = str(bytes.fromhex(data[8 + offset + 64:8 + offset + 64 + length]), 'utf8')
    return message


class BaseNeonCliErrorParser:
    def __init__(self, msg: str):
        self._code = 3
        self._msg = msg

    def execute(self, _) -> (str, int):
        return self._msg, self._code


class ProxyConfigErrorParser(BaseNeonCliErrorParser):
    def __init__(self, msg: str):
        BaseNeonCliErrorParser.__init__(self, msg)
        self._code = 4

    def execute(self, _) -> (str, int):
        return f'error in Neon Proxy configuration: {self._msg}', self._code


class ElfParamErrorParser(BaseNeonCliErrorParser):
    def __init__(self, msg: str):
        BaseNeonCliErrorParser.__init__(self, msg)
        self._code = 4

    def execute(self, _) -> (str, int):
        return f'error on reading ELF parameters from Neon EVM program: {self._msg}', self._code


class StorageErrorParser(BaseNeonCliErrorParser):
    def execute(self, _) -> (str, int):
        return f'error on reading storage of contract: {self._msg}', self._code


@logged_group("neon.Proxy")
class ProgramErrorParser(BaseNeonCliErrorParser):
    def __init__(self, msg: str):
        BaseNeonCliErrorParser.__init__(self, msg)
        self._code = -32000

    def execute(self, err: subprocess.CalledProcessError) -> (str, int):
        value = None
        msg = 'unknown error'

        is_first_hdr = True
        hdr = 'NeonCli Error (111): '
        funds_hdr = 'NeonCli Error (111): Solana program error. InsufficientFunds'

        for line in reversed(err.stderr.split('\n')):
            pos = line.find(hdr)
            if pos == -1:
                continue

            if is_first_hdr:
                msg = line[pos + len(hdr):]
                if line.find(funds_hdr) == -1:
                    break

                hdr = 'executor transfer from='
                is_first_hdr = False
                continue

            if not value:
                hdr = line[pos + len(hdr):]
                value_hdr = 'value='
                pos = hdr.find(value_hdr)
                value = hdr[pos + len(value_hdr):]
                pos = hdr.find('…')
                hdr = hdr[:pos]
            else:
                account = line[pos:]
                pos = account.find(' ')
                account = account[:pos]
                msg = f'insufficient funds for transfer: address {account} want {value}'
                break
        return msg, self._code


class FindAccount(BaseNeonCliErrorParser):
    def __init__(self, msg: str):
        BaseNeonCliErrorParser.__init__(self, msg)
        self._code = -32000

    @staticmethod
    def _find_account(line_list: [str], hdr: str) -> str:
        account = None
        for line in reversed(line_list):
            pos = line.find(hdr)  # NeonCli Error (212): Uninitialized account.  account=
            if pos == -1:
                continue
            if not account:
                account = line[pos + len(hdr):]
                pos = account.find(',')
                account = account[:pos]
                hdr = ' => ' + account  # Not found account for 0x1c074b10a40b95d1cfad9da99a59fb6aab20b694 => kNEjs3pevk1fdhkQDUDc1E9eEj4V5puXAwLgMuf5KAE
            else:
                account = line[:pos]
                pos = account.rfind(' ')
                account = account[pos + 1:]
                break
        if not account:
            account = 'Unknown'
        return account


class AccountAlreadyInitializedParser(FindAccount):
    def execute(self, err: subprocess.CalledProcessError) -> (str, int):
        msg = 'error on trying to initialize already initialized contract: '
        hdr = 'NeonCli Error (213): Account is already initialized.  account='
        account = self._find_account(err.stderr.split('\n'), hdr)
        return msg + account, self._code


class DeployToExistingAccountParser(FindAccount):
    def execute(self, err: subprocess.CalledProcessError) -> (str, int):
        msg = 'error on trying to deploy contract to user account: '
        hdr = 'NeonCli Error (221): Attempt to deploy to existing account at address '
        account = self._find_account(err.stderr.split('\n'), hdr)
        return msg + account, self._code


class TooManyStepsErrorParser(BaseNeonCliErrorParser):
    pass


class TrxCountOverflowErrorParser(BaseNeonCliErrorParser):
    pass


class NeonCliErrorParser:
    ERROR_PARSER_DICT = {
        102: ProxyConfigErrorParser('cannot read/write data to/from disk'),
        113: ProxyConfigErrorParser('connection problem with Solana node'),
        201: ProxyConfigErrorParser('evm loader is not specified'),
        202: ProxyConfigErrorParser('no information about signer'),

        111: ProgramErrorParser('ProgramError'),

        205: ElfParamErrorParser('account not found'),
        226: ElfParamErrorParser('account is not BPF compiled'),
        227: ElfParamErrorParser('account is not upgradeable'),
        241: ElfParamErrorParser('associated PDA not found'),
        242: ElfParamErrorParser('invalid associated PDA'),

        206: StorageErrorParser('account not found at address'),
        208: StorageErrorParser('code account required'),
        215: StorageErrorParser('contract account expected'),

        213: AccountAlreadyInitializedParser('AccountAlreadyInitialized'),

        221: DeployToExistingAccountParser('DeployToExistingAccount'),

        245: TooManyStepsErrorParser('execution requires too lot of EVM steps'),

        249: TrxCountOverflowErrorParser('transaction counter overflow')
    }

    def execute(self, caption: str, err: subprocess.CalledProcessError) -> (str, int):
        parser = self.ERROR_PARSER_DICT.get(err.returncode)
        if not parser:
            return f'Unknown {caption} error: {err.returncode}', 3
        return parser.execute(err)


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    try:
        neon_token_mint = ElfParams().neon_token_mint
        chain_id = ElfParams().chain_id
        return neon_cli().call("emulate", "--token_mint", str(neon_token_mint), "--chain_id", str(chain_id), sender, contract, data, value)
    except subprocess.CalledProcessError as err:
        msg, code = NeonCliErrorParser().execute('emulator', err)
        raise EthereumError(message=msg, code=code)
