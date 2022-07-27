import re
import base64

from typing import Any, Dict, List
from logged_groups import logged_group

from .environment_data import EVM_LOADER_ID
from .utils import NeonTxResultInfo
from .data import NeonTxReturn, NeonEvent, NeonLogIx


@logged_group("neon.Decoder")
def decode_neon_tx_return(data: List[str], logger) -> NeonTxReturn:
    """Unpacks base64-encoded return data"""
    if len(data) < 2:
        logger.error('Failed to decode return data')
        return None
    bs = base64.b64decode(data[0])
    exit_status = int.from_bytes(bs, "little")
    exit_status = 0x1 if exit_status < 0xd0 else 0x0
    bs = base64.b64decode(data[1])
    gas_used = int.from_bytes(bs, "little")
    return_value = b''
    if len(data) > 2:
        return_value = base64.b64decode(data[2])
    return NeonTxReturn(exit_status, gas_used, return_value)


@logged_group("neon.Decoder")
def decode_neon_event(data: List[str], *, logger) -> NeonEvent:
    """Unpacks base64-encoded event data"""
    if len(data) < 3:
        logger.error('Failed to decode events data: less then 3 elements in {data}')
        return None
    address = base64.b64decode(data[0])
    count_topics = int.from_bytes(base64.b64decode(data[1]), 'little')
    if count_topics > 4:
        logger.error(f'Failed to decode events data: count of topics more than 4 = {count_topics}')
        return None
    t = []
    for i in range(count_topics):
        t.append(base64.b64decode(data[2 + i]))
    log_data = b''
    log_data_index = 2 + count_topics
    if log_data_index < len(data):
        log_data = base64.b64decode(data[log_data_index])
    return NeonEvent(address, count_topics, t, log_data)


@logged_group("neon.Decoder")
def decode_neon_log_instructions(logs: List[str], logger) -> List[NeonLogIx]:
    """Reads log messages from a transaction receipt. Parses each line to rebuild sequence of Neon instructions. Extracts return and events information from these lines."""
    program_invoke = re.compile(r'^Program (\w+) invoke \[(\d+)\]')
    program_failed = re.compile(r'^Program (\w+) failed')
    program_data = re.compile(r'^Program data: (.+)$')
    tx_list: List[NeonLogIx] = []

    for line in logs:
        match = program_invoke.match(line)
        if match:
            program_id = match.group(1)
            if program_id == EVM_LOADER_ID:
                tx_list.append(NeonLogIx())
        match = program_failed.match(line)
        if match:
            program_id = match.group(1)
            if program_id == EVM_LOADER_ID:
                tx_list.pop(-1)  # remove failed invocation
        match = program_data.match(line)
        if match:
            tail = match.group(1)
            data = re.findall("\S+", tail)
            mnemonic = base64.b64decode(data[0]).decode('utf-8')
            if mnemonic == "RETURN":
                tx_list[-1].neon_return = decode_neon_tx_return(data[1:])
            elif mnemonic.startswith("LOG"):
                tx_list[-1].neon_events.append(decode_neon_event(data[1:]))
            else:
                logger.error(f'Failed to decode log instructions, unexpected mnemonic: {mnemonic}, instruction line: {line}')
                raise Exception('Failed to decode log instructions, unexpected mnemonic: %s, instruction line: %s' % (mnemonic, line))

    return tx_list


def decode_neon_tx_result(info: NeonTxResultInfo, neon_sign: str, tx: Dict[Any, Any], ix_idx=-1) -> NeonTxResultInfo:
    """Extracts Neon transaction result information"""
    log = decode_neon_log_instructions(tx['meta']['logMessages'])

    if ix_idx < 0:
        ix_idx = 0

    if ix_idx >= 0:
        log_ix = log[ix_idx]

        if log_ix.neon_return is not None:
            if info.slot != -1:
                info.warning(f'NeonTxResultInfo already loaded')
            info.gas_used = hex(log_ix.neon_return.gas_used)
            info.status = hex(log_ix.neon_return.exit_status)
            info.return_value = log_ix.neon_return.return_value.hex()
            info.sol_sign = tx['transaction']['signatures'][0]
            info.slot = tx['slot']
            info.idx = ix_idx

        log_idx = len(info.logs)
        for e in log_ix.neon_events:
            topics = []
            for i in range(e.count_topics):
                topics.append('0x' + e.topics[i].hex())
            rec = {
                'address': '0x' + e.address.hex(),
                'topics': topics,
                'data': '0x' + e.log_data.hex(),
                'transactionLogIndex': hex(log_idx),
                'transactionIndex': hex(info.idx),
                'logIndex': hex(log_idx),
                'transactionHash': neon_sign,
            }
            info.logs.append(rec)

        if len(info.logs) > 0:
            assert info.slot != -1, 'Events without result'

    return info
