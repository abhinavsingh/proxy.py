from __future__ import annotations

import json
import re

from logged_groups import logged_group
from typing import Union, Optional, Any, Tuple
from .utils import get_from_dict


class SolTxError(Exception):
    def __init__(self, receipt: dict):
        self.result = receipt

        log_list = SolReceiptParser(receipt).get_log_list()
        self.error = '. '.join([log for log in log_list if self._is_program_log(log)])
        if not len(self.error):
            self.error = json.dumps(receipt)

        super().__init__(self.error)

    @staticmethod
    def _is_program_log(log: str) -> bool:
        if log.startswith('Program log: Total memory occupied: '):
            return False

        prefix_list = (
            'Program log: ',
            'Program failed to complete: '
        )
        for prefix in prefix_list:
            if log.startswith(prefix):
                return True
        return False


@logged_group("neon.Proxy")
class SolReceiptParser:
    COMPUTATION_BUDGET_EXCEEDED = 'ComputationalBudgetExceeded'
    PROGRAM_FAILED_TO_COMPLETE = 'ProgramFailedToComplete'
    PROGRAM_EXCEED_INSTRUCTIONS = 'Program failed to complete: exceeded maximum number of instructions allowed'
    READ_ONLY_BLOCKED = "trying to execute transaction on ro locked account"
    READ_WRITE_BLOCKED = "trying to execute transaction on rw locked account"
    ALT_INVALID_INDEX = 'invalid transaction: Transaction address table lookup uses an invalid index'
    BLOCKHASH_NOTFOUND = 'BlockhashNotFound'
    NUMSLOTS_BEHIND = 'numSlotsBehind'

    NONCE_RE = re.compile('Program log: [a-z/.]+:\d+ : Invalid Ethereum transaction nonce: acc (\d+), trx (\d+)')

    def __init__(self, receipt: Union[dict, Exception, str]):
        if isinstance(receipt, SolTxError):
            self._receipt = receipt.result
        else:
            self._receipt = receipt
        self._log_list = []
        self._is_log_list_init = False
        self._error: Union[str, list, None] = None
        self._is_error_init = False
        self._error_code_msg: Optional[Tuple[int, str]] = None
        self._is_error_code_msg_init = False

    @staticmethod
    def raise_budget_exceeded():
        raise SolTxError({
            'err': {
                'InstructionError': [1, SolReceiptParser.COMPUTATION_BUDGET_EXCEEDED]
            }
        })

    def _get_value(self, *path) -> Any:
        if not self._receipt:
            return None
        if isinstance(self._receipt, Exception):
            return None

        return get_from_dict(self._receipt, *path)

    def _get_error(self) -> Union[str, list, None]:
        if not self._receipt:
            return None
        if isinstance(self._receipt, Exception):
            return str(self._receipt)

        err_from_receipt = self._get_value('result', 'meta', 'err', 'InstructionError')
        if err_from_receipt is not None:
            return err_from_receipt

        err_from_receipt_result = self._get_value('meta', 'err', 'InstructionError')
        if err_from_receipt_result is not None:
            return err_from_receipt_result

        err_from_send_trx_error = self._get_value('data', 'err', 'InstructionError')
        if err_from_send_trx_error is not None:
            return err_from_send_trx_error

        err_from_send_trx_error = self._get_value('data', 'err')
        if err_from_send_trx_error is not None:
            return err_from_send_trx_error

        err_from_prepared_receipt = self._get_value('err', 'InstructionError')
        if err_from_prepared_receipt is not None:
            return err_from_prepared_receipt

        return None

    def get_error(self) -> Union[str, list, None]:
        if not self._is_error_init:
            self._is_error_init = True
            self._error = self._get_error()
        return self._error

    def _get_error_code_msg(self) -> Optional[Tuple[int, str]]:
        if not self._receipt:
            return None
        if isinstance(self._receipt, Exception):
            return None

        code = self._get_value('code')
        msg = self._get_value('message')

        if (code is None) or (msg is None):
            return None
        return code, msg

    def get_error_code_msg(self) -> Optional[Tuple[int, str]]:
        if not self._is_error_code_msg_init:
            self._is_error_code_msg_init = True
            self._error_code_msg = self._get_error_code_msg()
        return self._error_code_msg

    def _get_log_list(self) -> [str]:
        if not self._receipt:
            return []
        if isinstance(self._receipt, Exception):
            return []

        log_from_receipt = self._get_value('result', 'meta', 'logMessages')
        if log_from_receipt is not None:
            return log_from_receipt

        log_from_receipt_result = self._get_value('meta', 'logMessages')
        if log_from_receipt_result is not None:
            return log_from_receipt_result

        log_from_receipt_result_meta = self._get_value('logMessages')
        if log_from_receipt_result_meta is not None:
            return log_from_receipt_result_meta

        log_from_send_trx_error = self._get_value('data', 'logs')
        if log_from_send_trx_error is not None:
            return log_from_send_trx_error

        log_from_prepared_receipt = self._get_value('logs')
        if log_from_prepared_receipt is not None:
            return log_from_prepared_receipt

        return []

    def get_log_list(self):
        if not self._is_log_list_init:
            self._is_log_list_init = True
            self._log_list = self._get_log_list()
        return self._log_list

    def check_if_error(self) -> bool:
        return (self.get_error() is not None) or (self.get_error_code_msg() is not None)

    def check_if_big_transaction(self) -> bool:
        """This exception is generated by solana python library"""
        if isinstance(self._receipt, Exception):
            return str(self._receipt).startswith("transaction too large:")
        return False

    def check_if_budget_exceeded(self) -> bool:
        """Error can be received as receipt or can be result of throwing an Exception"""
        error_type = self.get_error()
        if not error_type:
            return False
        if isinstance(error_type, list):
            error_type = error_type[1]

        if not isinstance(error_type, str):
            return False

        if error_type == self.COMPUTATION_BUDGET_EXCEEDED:
            return True
        if error_type == self.PROGRAM_FAILED_TO_COMPLETE:
            log_list = self.get_log_list()
            for log in log_list:
                if log.startswith(self.PROGRAM_EXCEED_INSTRUCTIONS):
                    return True
        return False

    def check_if_accounts_blocked(self) -> bool:
        log_list = self.get_log_list()
        if not len(log_list):
            self.error(f"Can't get logs from receipt: {json.dumps(self._receipt, sort_keys=True)}")
            return False

        for log in log_list:
            if (log.find(self.READ_ONLY_BLOCKED) >= 0) or (log.find(self.READ_WRITE_BLOCKED) >= 0):
                return True
        return False

    def check_if_blockhash_notfound(self) -> bool:
        if not self._receipt:
            return True
        return self.get_error() == self.BLOCKHASH_NOTFOUND

    def get_slots_behind(self) -> Optional[int]:
        return self._get_value('data', self.NUMSLOTS_BEHIND)

    def check_if_alt_uses_invalid_index(self) -> bool:
        a = self.get_error_code_msg()
        return self.get_error_code_msg() == (-32602, self.ALT_INVALID_INDEX)

    def get_nonce_error(self) -> Optional[(int, int)]:
        log_list = self._get_log_list()
        for log in log_list:
            s = self.NONCE_RE.search(log)
            if s is not None:
                return s.groups()
        return None
