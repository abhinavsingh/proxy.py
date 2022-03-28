import json
import subprocess
from logged_groups import logged_group

from typing import Optional, Dict, Any
from .errors import EthereumError
from ..environment import neon_cli, NEON_TOKEN_MINT


@logged_group("neon.Proxy")
def call_emulated(contract_id, caller_id, data=None, value=None, *, logger):
    output = emulator(contract_id, caller_id, data, value)
    logger.debug(f"Call emulated. contract_id: {contract_id}, caller_id: {caller_id}, data: {data}, value: {value}, return: {output}")
    result = json.loads(output)
    check_emulated_exit_status(result)
    return result


@logged_group("neon.Proxy")
def check_emulated_exit_status(result: Dict[str, Any], *, logger):
    exit_status = result['exit_status']
    if exit_status == 'revert':
        revert_data = result['result']
        logger.debug(f"Got revert call emulated result with data: {revert_data}")
        result_value = decode_revert_message(revert_data)
        if result_value is None:
            raise EthereumError(code=3, message='execution reverted', data='0x' + revert_data)
        else:
            raise EthereumError(code=3, message='execution reverted: ' + result_value, data='0x' + revert_data)

    if exit_status != "succeed":
        logger.debug(f"Got not succeed emulate exit_status: {exit_status}")
        raise Exception("evm emulator error ", result)


@logged_group("neon.Proxy")
def decode_revert_message(data: str, *, logger) -> Optional[str]:
    data_len = len(data)
    if data_len == 0:
        return None

    if data_len < 8:
        raise Exception(f"Too less bytes to decode revert signature: {data_len}, data: 0x{data}")

    if data[:8] == '4e487b71': # keccak256("Panic(uint256)")
        return None

    if data[:8] != '08c379a0': # keccak256("Error(string)")
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


def parse_emulator_program_error(stderr):
    last_line = stderr[-1]
    if stderr[-1].find('NeonCli Error (111): Solana program error. InsufficientFunds'):
        return 'insufficient funds for transfer'
    hdr = 'NeonCli Error (111): '
    pos = last_line.find(hdr)
    if pos == -1:
        return last_line
    return last_line[pos + len(hdr):]


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    try:
        return neon_cli().call("emulate", "--token_mint", str(NEON_TOKEN_MINT), sender, contract, data, value)
    except subprocess.CalledProcessError as err:
        if err.returncode == 111:
            message = parse_emulator_program_error(err.stderr)
        elif err.returncode == 102:
            message = 'Emulator error: StdIoError'
        elif err.returncode == 112:
            message = 'Emulator error: SignerError'
        elif err.returncode == 113:
            message = 'Emulator error: ClientError'
        elif err.returncode == 114:
            message = 'Emulator error: CliError'
        elif err.returncode == 115:
            message = 'Emulator error: TpuSenderError'
        elif err.returncode == 201:
            message = 'Emulator error: EvmLoaderNotSpecified'
        elif err.returncode == 202:
            message = 'Emulator error: FeePayerNotSpecified'
        elif err.returncode == 205:
            message = 'Emulator error: AccountNotFound'
        elif err.returncode == 206:
            message = 'Emulator error: AccountNotFoundAtAddress'
        elif err.returncode == 207:
            message = 'Emulator error: CodeAccountNotFound'
        elif err.returncode == 208:
            message = 'Emulator error: CodeAccountRequired'
        elif err.returncode == 209:
            message = 'Emulator error: IncorrectAccount'
        elif err.returncode == 210:
            message = 'Emulator error: AccountAlreadyExists'
        elif err.returncode == 212:
            message = 'Emulator error: AccountUninitialized'
        elif err.returncode == 213:
            message = 'Emulator error: AccountAlreadyInitialized'
        elif err.returncode == 215:
            message = 'Emulator error: ContractAccountExpected'
        elif err.returncode == 221:
            message = 'Emulator error: DeploymentToExistingAccount'
        elif err.returncode == 222:
            message = 'Emulator error: InvalidStorageAccountOwner'
        elif err.returncode == 223:
            message = 'Emulator error: StorageAccountRequired'
        elif err.returncode == 224:
            message = 'Emulator error: AccountIncorrectType'
        elif err.returncode == 225:
            message = 'Emulator error: AccountDataTooSmall'
        elif err.returncode == 226:
            message = 'Emulator error: AccountIsNotBpf'
        elif err.returncode == 227:
            message = 'Emulator error: AccountIsNotUpgradeable'
        elif err.returncode == 230:
            message = 'Emulator error: ConvertNonceError'
        elif err.returncode == 241:
            message = 'Emulator error: AssociatedPdaNotFound'
        elif err.returncode == 242:
            message = 'Emulator error: InvalidAssociatedPda'
        elif err.returncode == 243:
            message = 'Emulator error: InvalidVerbosityMessage'
        elif err.returncode == 244:
            message = 'Emulator error: TransactionFailed'
        elif err.returncode == 245:
            message = 'Emulator error: Too many steps'
        else:
            message = 'Emulator error: UnknownError'
        raise EthereumError(message=message)

