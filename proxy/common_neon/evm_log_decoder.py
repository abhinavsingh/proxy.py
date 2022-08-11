import re
import base64

from typing import List, Iterator
from logged_groups import logged_group

from .utils import NeonTxResultInfo


@logged_group("neon.Decoder")
def decode_neon_tx_return(data_list: List[str], neon_sig: str, neon_tx_res: NeonTxResultInfo, *, logger) -> None:
    """Unpacks base64-encoded return data"""
    if len(data_list) < 2:
        logger.error(f'Failed to decode return data {data_list} for Neon Tx {neon_sig}')
        return

    if neon_tx_res.is_valid():
        raise RuntimeError(f'Neon Tx {neon_sig} already has result')

    bs = base64.b64decode(data_list[0])
    exit_status = int.from_bytes(bs, "little")
    exit_status = 0x1 if exit_status < 0xd0 else 0x0
    bs = base64.b64decode(data_list[1])
    gas_used = int.from_bytes(bs, "little")
    return_value = b''
    if len(data_list) > 2:
        return_value = base64.b64decode(data_list[2])

    neon_tx_res.fill_result(gas_used=hex(gas_used), status=hex(exit_status), return_value=return_value.hex())


@logged_group("neon.Decoder")
def decode_neon_event(data_list: List[str], neon_sig: str, neon_tx_res: NeonTxResultInfo, *, logger) -> None:
    """Unpacks base64-encoded event data"""
    if len(data_list) < 3:
        logger.error(f'Failed to decode events data: less then 3 elements in {data_list} for Neon Tx {neon_sig}')
        return None

    topic_cnt = int.from_bytes(base64.b64decode(data_list[1]), 'little')
    if topic_cnt > 4:
        logger.error(f'Failed to decode events data: count of topics more than 4 = {topic_cnt} for Neon Tx {neon_sig}')
        return None

    address = base64.b64decode(data_list[0])
    topic_list: List[bytes] = []
    for i in range(topic_cnt):
        topic_list.append(base64.b64decode(data_list[2 + i]))
    log_data = b''
    log_data_index = 2 + topic_cnt
    if log_data_index < len(data_list):
        log_data = base64.b64decode(data_list[log_data_index])

    tx_log_idx = len(neon_tx_res.log_list)
    rec = {
        'address': '0x' + address.hex(),
        'topics': ['0x' + topic.hex() for topic in topic_list],
        'data': '0x' + log_data.hex(),
        'transactionHash': neon_sig,
        'transactionLogIndex': hex(tx_log_idx),
        # 'logIndex': hex(tx_log_idx), # set when transaction found
        # 'transactionIndex': hex(ix.idx), # set when transaction found
        # 'blockNumber': block_number, # set when transaction found
        # 'blockHash': block_hash # set when transaction found
    }
    neon_tx_res.append_record(rec)


class _ProgramData:
    re_data = re.compile(r'^Program data: (.+)$')


@logged_group("neon.Decoder")
def decode_neon_tx_result(log_iter: Iterator[str], neon_sig: str, neon_tx_res: NeonTxResultInfo, *, logger) -> bool:
    """Extracts Neon transaction result information"""

    data_cnt = 0
    for line in log_iter:
        match = _ProgramData.re_data.match(line)
        if match is None:
            continue

        data_cnt += 1
        tail: str = match.group(1)
        data_list = tail.split()
        mnemonic = base64.b64decode(data_list[0]).decode('utf-8')
        if mnemonic == "RETURN":
            decode_neon_tx_return(data_list[1:], neon_sig, neon_tx_res)
        elif mnemonic.startswith("LOG"):
            decode_neon_event(data_list[1:], neon_sig, neon_tx_res)
        else:
            raise RuntimeError(
                f'Failed to decode log instructions for Neon Tx {neon_sig}, ' +
                f'unexpected mnemonic: {mnemonic}, instruction line: {line}'
            )

    if data_cnt == 0:
        return False

    if (len(neon_tx_res.log_list) > 0) and (not neon_tx_res.is_valid()):
        logger.warning(f'Neon Tx {neon_sig} has events without result')
        neon_tx_res.fill_result(gas_used='0x0', status='0x0', return_value='')

    return neon_tx_res.is_valid()
