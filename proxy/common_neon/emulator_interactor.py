import json
from logged_groups import logged_group

from typing import Optional, Dict, Any
from .errors import EthereumError
from ..environment import neon_cli, ETH_TOKEN_MINT_ID


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


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    return neon_cli().call("emulate", "--token_mint", str(ETH_TOKEN_MINT_ID), sender, contract, data, value)
