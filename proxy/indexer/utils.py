from __future__ import annotations
import re

import statistics

from solana.publickey import PublicKey
from logged_groups import logged_group
from typing import Any, Dict, List, Union, Callable
from dataclasses import astuple, dataclass

from ..common_neon.address import ether2program
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT, ACCOUNT_INFO_LAYOUT
from ..common_neon.solana_interactor import SolanaInteractor

from ..environment import INDEXER_LOG_SKIP_COUNT



def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        return True
    return False


class SolanaIxSignInfo:
    def __init__(self, sign: str, slot: int, idx: int):
        self.sign = sign  # Solana transaction signature
        self.slot = slot  # Solana block slot
        self.idx  = idx   # Instruction index
        self.steps = None # Instruction index

    def __str__(self):
        return f'{self.slot} {self.sign} {self.idx}'

    def __hash__(self):
        return hash((self.sign, self.slot, self.idx))

    def __eq__(self, other):
        return (self.sign, self.slot, self.idx) == (other.sign, other.slot, other.idx)

    def get_req_id(self):
        return f"{self.idx}{self.sign}"[:7]

    def set_steps(self, steps: int):
        self.steps = steps


@dataclass
class CostInfo:
    sign: str = None
    operator: str = None
    heap: int = 0
    bpf: int = 0
    sol_spent: int = 0
    neon_income: int = 0

    def __init__(self, sign: str, tx: Dict[str, Any], program: PublicKey):
        self.sign = sign
        if tx:
            self.init_from_tx(tx, program)

    def __iter__(self):
        return iter(astuple(self))

    def init_from_tx(self, tx: dict, program: PublicKey):
        self.operator = tx['transaction']['message']['accountKeys'][0]
        self.sol_spent = tx['meta']['preBalances'][0] - tx['meta']['postBalances'][0]

        self.fill_heap_bpf_from_logs(tx['meta']['logMessages'], program)
        self.fill_neon_income(tx['meta']['preTokenBalances'], tx['meta']['postTokenBalances'])

    def fill_heap_bpf_from_logs(self, log_messages: List[str], program: PublicKey):
        for log in log_messages:
            self.bpf = max(self.bpf, CostInfo.bpf_log(program, log))
            self.heap = max(self.heap, CostInfo.heap_log(log))

    def fill_neon_income(self, pre_balances: List[str], post_balances: List[str]):
        pre_token = 0
        post_token = 0
        for balance in pre_balances:
            if balance['owner'] == self.operator:
                pre_token = int(balance["uiTokenAmount"]["amount"])
        for balance in post_balances:
            if balance['owner'] == self.operator:
                post_token = int(balance["uiTokenAmount"]["amount"])
        self.neon_income = post_token - pre_token

    @staticmethod
    def bpf_log(program: PublicKey, logging_note: str):
        match = re.match(f"Program {program} consumed (\d+) of \d+ compute units", logging_note)
        return 0 if match is None else int(match[1])

    @staticmethod
    def heap_log(logging_note: str):
        match = re.match(f"Program log: Total memory occupied: (\d+)", logging_note)
        return 0 if match is None else int(match[1])


class MetricsToLogBuff:
    def __init__(self):
        self._reset()

    def _reset(self):
        self.counter = 0
        self.items_list = {}
        self.items_latest = {}

    def print(self, logger: Callable[[str], None], list_params: Dict[str, Union[int, float]], latest_params: Dict[str, int]):
        for key, value in list_params.items():
            metric_list = self.items_list.setdefault(key, [])
            metric_list.append(value)
        for key, value in latest_params.items():
            self.items_latest[key] = value
        self.counter += 1

        if self.counter % INDEXER_LOG_SKIP_COUNT != 0:
            return

        msg = ''
        for key, value_list in self.items_list.items():
            msg += f' {key} avg: {statistics.mean(value_list):.2f}'
            msg += f' min: {min(value_list):.2f}'
            msg += f' max: {max(value_list):.2f};'
        for key, value in self.items_latest.items():
            msg += f' {key}: {value};'
        logger(msg)
        self._reset()
