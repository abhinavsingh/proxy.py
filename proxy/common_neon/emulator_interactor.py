import json
import logging

from .errors import EthereumError
from ..environment import neon_cli


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def call_emulated(contract_id, caller_id, data=None, value=None):
    output = emulator(contract_id, caller_id, data, value)
    logger.debug("call_emulated %s %s %s %s return %s", contract_id, caller_id, data, value, output)
    result = json.loads(output)
    exit_status = result['exit_status']
    if exit_status == 'revert':
        result_value = result['result']
        if len(result_value) < 8 or result_value[:8] != '08c379a0':
            raise EthereumError(code=3, message='execution reverted')

        offset = int(result_value[8:8+64], 16)
        length = int(result_value[8+64:8+64+64], 16)
        message = str(bytes.fromhex(result_value[8+offset*2+64:8+offset*2+64+length*2]), 'utf8')
        raise EthereumError(code=3, message='execution reverted: '+message, data='0x'+result_value)
    if result["exit_status"] != "succeed":
        raise Exception("evm emulator error ", result)
    return result


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    return neon_cli().call("emulate", sender, contract, data, value)
