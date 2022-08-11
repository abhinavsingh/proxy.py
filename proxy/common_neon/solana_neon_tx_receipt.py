from __future__ import annotations

from typing import Optional, Dict, Union, Iterator, List, Any, Tuple, NamedTuple, cast

import re
import base58

from enum import Enum
from logged_groups import logged_group

from ..common_neon.utils import str_fmt_object
from ..common_neon.environment_data import EVM_LOADER_ID


class SolTxSigSlotInfo(NamedTuple):
    sol_sig: str
    block_slot: int

    def __str__(self) -> str:
        return f'{self.block_slot}:{self.sol_sig}'


class SolTxMetaInfo:
    def __init__(self, block_slot: int, sol_sig: str, tx: Dict[str, Any]):
        self._sol_sig = sol_sig
        self._block_slot = block_slot
        self._tx = tx

    @property
    def ident(self) -> SolTxSigSlotInfo:
        return SolTxSigSlotInfo(block_slot=self._block_slot, sol_sig=self._sol_sig)

    def __str__(self) -> str:
        return str(self.ident)

    @staticmethod
    def from_response(sig_slot: SolTxSigSlotInfo, response: Dict[str, Any]) -> SolTxMetaInfo:
        return SolTxMetaInfo(block_slot=sig_slot.block_slot, sol_sig=sig_slot.sol_sig, tx=response)

    @property
    def sol_sig(self) -> str:
        return self._sol_sig

    @property
    def block_slot(self) -> int:
        return self._block_slot

    @property
    def tx(self) -> Dict[str, Any]:
        return self._tx


class _SolIxSuccessLog:
    def __init__(self, program: str):
        self._program = program

    @property
    def program(self) -> str:
        return self._program


class _SolIxFailedLog:
    def __init__(self, program: str, error: str):
        self._program = program
        self._error = error

    @property
    def program(self) -> str:
        return self._program

    @property
    def error(self) -> str:
        return self._error


class _SolIxInvokeLog:
    def __init__(self, program: str, level: int):
        self._program = program
        self._level = level

    @property
    def program(self) -> str:
        return self._program

    @property
    def level(self) -> int:
        return self._level


_SolIxStatusLog = Union[None, _SolIxSuccessLog, _SolIxFailedLog]


class SolIxLogList:
    class Status(Enum):
        UNKNOWN = 0
        SUCCESS = 1
        FAILED = 2

    def __init__(self, program: str, level: int):
        self._program = program
        self._level = level
        self._status = self.Status.UNKNOWN
        self._error: Optional[str] = None
        self.log_list: List[Union[str, SolIxLogList]] = []
        self.inner_log_list: List[SolIxLogList] = []

    def __str__(self) -> str:
        return str_fmt_object(self)

    @property
    def program(self) -> str:
        return self._program

    @property
    def level(self) -> int:
        return self._level

    @property
    def status(self) -> SolIxLogList.Status:
        return self._status

    @property
    def error(self) -> str:
        assert self._error is not None
        return cast(str, self._error)

    def set_status(self, status: _SolIxStatusLog) -> None:
        assert self._status == self.status.UNKNOWN
        if isinstance(status, _SolIxSuccessLog):
            assert status.program == self.program
            self._status = self.Status.SUCCESS
        elif isinstance(status, _SolIxFailedLog):
            assert status.program == self.program
            self._status = self.Status.FAILED
            self._error = status.error
        else:
            assert False, f'unknown status {status}'


class _SolTxLogParser:
    _invoke_re = re.compile(r'^Program (\w+) invoke \[(\d+)]$')
    _success_re = re.compile(r'^Program (\w+) success$')
    _failed_re = re.compile(r'^Program (\w+) failed: (.+)$')

    def __init__(self):
        self._log_msg_iter: Optional[Iterator[str]] = None

    def parse(self, log_msg_list: List[str]) -> List[SolIxLogList]:
        log_state = SolIxLogList('', 0)
        self._log_msg_iter = iter(log_msg_list)
        self._parse(log_state)
        self._log_msg_iter = None
        return log_state.inner_log_list

    def _parse(self, log_state: SolIxLogList) -> _SolIxStatusLog:
        for log_msg in self._log_msg_iter:
            invoke = self._get_invoke(log_msg)
            if invoke:
                ix_log_state = SolIxLogList(invoke.program, invoke.level)

                log_state.log_list.append(ix_log_state)
                log_state.inner_log_list.append(ix_log_state)

                next_log_state = SolIxLogList(invoke.program, invoke.level)
                next_log_state.log_list = ix_log_state.log_list
                if invoke.level > 1:
                    next_log_state.inner_log_list = log_state.inner_log_list
                else:
                    next_log_state.inner_log_list = ix_log_state.inner_log_list

                status = self._parse(next_log_state)
                if status is not None:
                    ix_log_state.set_status(status)
                continue

            success = self._get_success(log_msg)
            if success:
                return success

            failed = self._get_failed(log_msg)
            if failed:
                return failed

            log_state.log_list.append(log_msg)
        return None

    def _get_invoke(self, log_msg: str) -> Optional[_SolIxInvokeLog]:
        match = self._invoke_re.match(log_msg)
        if match is not None:
            return _SolIxInvokeLog(program=match[1], level=int(match[2]))
        return None

    def _get_success(self, log_msg: str) -> Optional[_SolIxSuccessLog]:
        match = self._success_re.match(log_msg)
        if match is not None:
            return _SolIxSuccessLog(program=match[1])
        return None

    def _get_failed(self, log_msg: str) -> Optional[_SolIxFailedLog]:
        match = self._failed_re.match(log_msg)
        if match is not None:
            return _SolIxFailedLog(program=match[1], error=match[2])
        return None


class SolIxMetaInfo:
    def __init__(self, ix: Dict[str, Any], idx: int, log_list: SolIxLogList, inner_idx: Optional[int] = None):
        self._ix = ix
        self._idx = idx
        self._inner_idx = inner_idx
        self._log_list = log_list

    @property
    def ix(self) -> Dict[str, Any]:
        return self._ix

    @property
    def idx(self) -> int:
        return self._idx

    @property
    def inner_idx(self) -> Optional[int]:
        return self._inner_idx

    @property
    def program(self) -> str:
        return self._log_list.program

    @property
    def level(self) -> int:
        return self._log_list.level

    @property
    def status(self) -> SolIxLogList.Status:
        return self._log_list.status

    @property
    def error(self) -> str:
        return self._log_list.error

    def iter_log(self) -> Iterator[str]:
        for log in self._log_list.log_list:
            if isinstance(log, str):
                yield log


class SolTxCostInfo:
    def __init__(self, tx_meta: SolTxMetaInfo):
        self._sol_sig = tx_meta.sol_sig
        self._block_slot = tx_meta.block_slot

        msg = tx_meta.tx['transaction']['message']
        self._operator = msg['accountKeys'][0]

        meta = tx_meta.tx['meta']
        self._sol_spent = meta['preBalances'][0] - meta['postBalances'][0]

    def __str__(self) -> str:
        return str_fmt_object(self)

    def __hash__(self) -> int:
        return hash(self._sol_sig)

    @property
    def sol_sig(self) -> str:
        return self._sol_sig

    @property
    def block_slot(self) -> int:
        return self._block_slot

    @property
    def operator(self) -> str:
        return self._operator

    @property
    def sol_spent(self) -> int:
        return self._sol_spent


@logged_group("neon.Parser")
class SolNeonIxReceiptInfo:
    _bpf_cycle_cnt_re = re.compile(f'^Program {EVM_LOADER_ID}' + r' consumed (\d+) of (\d+) compute units$')
    _heap_size_re = re.compile(r'^Program log: Total memory occupied: (\d+)$')

    def __init__(self, tx_meta: SolTxMetaInfo, ix_meta: SolIxMetaInfo, tx_cost: SolTxCostInfo):
        self._tx_meta = tx_meta
        self._ix_meta = ix_meta
        self._tx_cost = tx_cost

        msg = tx_meta.tx['transaction']['message']
        self._account_list = ix_meta.ix['accounts']

        self._account_key_list = msg['accountKeys']
        lookup_key_list = tx_meta.tx['meta'].get('loadedAddresses', None)
        if lookup_key_list is not None:
            self._account_key_list += lookup_key_list['writable'] + lookup_key_list['readonly']

        self._program_ix: Optional[int] = None
        self._ix_data: Optional[bytes] = None
        self._decode_ixdata()

        self._heap_size = 0
        self._used_bpf_cycle_cnt = 0
        self._max_bpf_cycle_cnt = 0
        self._neon_step_cnt = 0
        self._neon_income = 0

        self._parse_log_list()

    def __str__(self) -> str:
        return ':'.join([str(s) for s in self.ident])

    def __hash__(self) -> int:
        return hash(self.ident)

    def __eq__(self, other: SolNeonIxReceiptInfo) -> bool:
        return self.ident == other.ident

    @property
    def sol_sig(self) -> str:
        return self._tx_meta.sol_sig

    @property
    def block_slot(self) -> int:
        return self._tx_meta.block_slot

    @property
    def sol_tx_cost(self) -> SolTxCostInfo:
        return self._tx_cost

    @property
    def idx(self) -> int:
        return self._ix_meta.idx

    @property
    def inner_idx(self) -> int:
        return self._ix_meta.inner_idx

    @property
    def level(self) -> int:
        return self._ix_meta.level

    @property
    def program(self) -> str:
        return self._ix_meta.program

    @property
    def program_ix(self) -> int:
        assert self._program_ix is not None
        return cast(int, self._program_ix)

    @property
    def ix_data(self) -> bytes:
        assert self._ix_data is not None
        return cast(bytes, self._ix_data)

    @property
    def heap_size(self) -> int:
        return self._heap_size

    @property
    def used_bpf_cycle_cnt(self) -> int:
        return self._used_bpf_cycle_cnt

    @property
    def max_bpf_cycle_cnt(self) -> int:
        return self._max_bpf_cycle_cnt

    @property
    def neon_step_cnt(self) -> int:
        return self._neon_step_cnt

    @property
    def neon_income(self) -> int:
        return self._neon_income

    def set_neon_step_cnt(self, value: int) -> None:
        assert self._neon_step_cnt == 0
        self._neon_step_cnt = value

    @property
    def ident(self) -> Tuple[int, str, int, Optional[int]]:
        return self._tx_meta.block_slot, self._tx_meta.sol_sig, self._ix_meta.idx, self._ix_meta.inner_idx

    def _parse_log_list(self) -> None:
        for log_msg in self._ix_meta.iter_log():
            if self._get_bpf_cycle_cnt(log_msg):
                continue
            elif self._get_heap_size(log_msg):
                continue
            elif self._get_neon_income(log_msg):
                continue

    def _get_bpf_cycle_cnt(self, log_msg: str) -> bool:
        match = self._bpf_cycle_cnt_re.match(log_msg)
        if match is None:
            return False

        self._used_bpf_cycle_cnt = int(match[1])
        self._max_bpf_cycle_cnt = int(match[2])
        return True

    def _get_heap_size(self, log_msg: str) -> bool:
        match = self._heap_size_re.match(log_msg)
        if match is None:
            return False

        self._heap_size = int(match[1])
        return True

    def _get_neon_income(self, log_msg: str) -> bool:
        # TODO: add parsing of NEON income
        pass

    def _decode_ixdata(self) -> bool:
        try:
            self._ix_data = base58.b58decode(self._ix_meta.ix['data'])
            self._program_ix = int(self.ix_data[0])
            return True
        except Exception as e:
            self.debug(f'{self} fail to get a program instruction: {e}')
            self._program_ix = None
            self._ix_data = None
        return False

    @property
    def account_cnt(self) -> int:
        return len(self._account_list)

    @property
    def req_id(self) -> str:
        return f"{hex(abs(hash(self)))}"[:7]

    def get_account(self, account_idx: int) -> str:
        if len(self._account_list) > account_idx:
            key_idx = self._account_list[account_idx]
            if len(self._account_key_list) > key_idx:
                return self._account_key_list[key_idx]
        return ''

    def iter_account(self, start_idx: int) -> Iterator[str]:
        for idx in self._account_list[start_idx:]:
            yield self._account_key_list[idx]

    def iter_log(self) -> Iterator[str]:
        return self._ix_meta.iter_log()


@logged_group("neon.Parser")
class SolTxReceiptInfo:
    def __init__(self, tx_meta: SolTxMetaInfo):
        self._tx_meta = tx_meta

        msg = tx_meta.tx['transaction']['message']
        self._ix_list = msg['instructions']
        self.operator = msg['accountKeys'][0]

        meta = tx_meta.tx['meta']
        self._inner_ix_list = meta['innerInstructions']
        self._log_msg_list = meta['logMessages']

        self._account_key_list = msg['accountKeys']
        lookup_key_list = meta.get('loadedAddresses', None)
        if lookup_key_list is not None:
            self._account_key_list += lookup_key_list['writable'] + lookup_key_list['readonly']

        self._sol_cost = SolTxCostInfo(tx_meta)

        self._ix_log_msg_list: List[SolIxLogList] = []
        self._parse_log_msg_list()

    @property
    def ident(self) -> Tuple[int, str]:
        return self._tx_meta.block_slot, self._tx_meta.sol_sig

    def __str__(self) -> str:
        return ':'.join([str(s) for s in self.ident])

    @property
    def sol_sig(self) -> str:
        return self._tx_meta.sol_sig

    @property
    def block_slot(self) -> int:
        return self._tx_meta.block_slot

    @property
    def sol_cost(self) -> SolTxCostInfo:
        return self._sol_cost

    def _add_missing_log_msgs(self, log_list: List[SolIxLogList],
                              ix_list: List[Dict[str, Any]],
                              level: int) -> List[SolIxLogList]:
        base_level = level

        def calc_level() -> int:
            if base_level == 1:
                return 1
            return level + 1

        result_log_list: List[SolIxLogList] = []

        log_iter = iter(log_list)
        log = next(log_iter)
        for idx, ix in enumerate(ix_list):
            ix_program_key = self._get_program_key(ix)
            if (log is None) or (log.program != ix_program_key):
                result_log_list.append(SolIxLogList(ix_program_key, calc_level()))
            else:
                level = log.level
                result_log_list.append(log)
                log = next(log_iter, None)

        assert len(result_log_list) == len(ix_list), f'{len(result_log_list)} == {len(ix_list)}'
        assert log is None
        return result_log_list

    def _parse_log_msg_list(self) -> None:
        log_parser = _SolTxLogParser()
        log_msg_list = log_parser.parse(self._log_msg_list)
        self._ix_log_msg_list = self._add_missing_log_msgs(log_msg_list, self._ix_list, 1)
        for ix_idx, ix in enumerate(self._ix_list):
            inner_ix_list = self._get_inner_ix_list(ix_idx)
            if len(inner_ix_list):
                log_msg_list = self._ix_log_msg_list[ix_idx]
                inner_log_msg_list = log_msg_list.inner_log_list
                log_msg_list.inner_log_list = self._add_missing_log_msgs(inner_log_msg_list, inner_ix_list, 2)

    def _get_program_key(self, ix: Dict[str, Any]) -> str:
        program_idx = ix.get('programIdIndex', None)
        if program_idx is None:
            self.warning(f'{self} error: fail to get program id')
            return ''
        elif program_idx > len(self._account_key_list):
            self.warning(f'{self} error: program index greater than list of accounts')
            return ''

        return self._account_key_list[program_idx]

    def _is_neon_program(self, ix: Dict[str, Any]) -> bool:
        return self._get_program_key(ix) == EVM_LOADER_ID

    def _get_log_list(self, ix_idx: int, inner_ix_idx: Optional[int] = None) -> Optional[SolIxLogList]:
        if ix_idx >= len(self._ix_log_msg_list):
            self.warning(f'{self} error: cannot find logs for instruction {ix_idx} > {len(self._ix_log_msg_list)}')
            return None

        ix_log_list = self._ix_log_msg_list[ix_idx]
        if inner_ix_idx is None:
            return ix_log_list

        if inner_ix_idx >= len(ix_log_list.inner_log_list):
            self.warning(f'{self} error: cannot find logs for instruction' +
                         f' {ix_idx}:{inner_ix_idx} > {len(ix_log_list.inner_log_list)}')
            return None
        return ix_log_list.inner_log_list[inner_ix_idx]

    def _get_inner_ix_list(self, ix_idx: int) -> List[Dict[str, Any]]:
        for inner_ix in self._inner_ix_list:
            if inner_ix['index'] == ix_idx:
                return inner_ix['instructions']
        return []

    def iter_sol_neon_ix(self) -> Iterator[SolNeonIxReceiptInfo]:
        for ix_idx, ix in enumerate(self._ix_list):
            if self._is_neon_program(ix):
                log_list = self._get_log_list(ix_idx)
                if log_list is not None:
                    ix_meta = SolIxMetaInfo(ix=ix, idx=ix_idx, log_list=log_list)
                    yield SolNeonIxReceiptInfo(tx_meta=self._tx_meta, ix_meta=ix_meta, tx_cost=self._sol_cost)

            inner_ix_list = self._get_inner_ix_list(ix_idx)
            for inner_idx, inner_ix in enumerate(inner_ix_list):
                if self._is_neon_program(inner_ix):
                    log_list = self._get_log_list(ix_idx, inner_idx)
                    if log_list is not None:
                        ix_meta = SolIxMetaInfo(ix=inner_ix, idx=ix_idx, inner_idx=inner_idx, log_list=log_list)
                        yield SolNeonIxReceiptInfo(tx_meta=self._tx_meta, ix_meta=ix_meta, tx_cost=self._sol_cost)
