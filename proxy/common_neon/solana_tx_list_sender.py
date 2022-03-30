from __future__ import annotations

import time

from logged_groups import logged_group
from typing import Optional
from solana.transaction import Transaction

from .costs import update_transaction_cost
from .solana_receipt_parser import SolReceiptParser, SolTxError
from .errors import EthereumError

from ..environment import WRITE_TRANSACTION_COST_IN_DB, SKIP_PREFLIGHT, RETRY_ON_FAIL


@logged_group("neon.Proxy")
class SolTxListSender:
    def __init__(self, sender, tx_list: [Transaction], name: str,
                 skip_preflight=SKIP_PREFLIGHT, preflight_commitment='confirmed'):
        self._s = sender
        self._name = name
        self._skip_preflight = skip_preflight
        self._preflight_commitment = preflight_commitment

        self._blockhash = None
        self._retry_idx = 0
        self._total_success_cnt = 0
        self._slots_behind = 0
        self._tx_list = tx_list
        self._node_behind_list = []
        self._bad_block_list = []
        self._blocked_account_list = []
        self._pending_list = []
        self._budget_exceeded_list = []
        self._budget_exceeded_receipt: Optional[dict] = None
        self._unknown_error_list = []

        self._all_tx_list = [self._node_behind_list,
                             self._bad_block_list,
                             self._blocked_account_list,
                             self._budget_exceeded_list,
                             self._pending_list]

    def clear(self):
        self._tx_list.clear()
        for lst in self._all_tx_list:
            lst.clear()
        self._budget_exceeded_receipt = None

    def _get_full_list(self):
        return [tx for lst in self._all_tx_list for tx in lst]

    def send(self) -> SolTxListSender:
        solana = self._s.solana
        signer = self._s.signer
        waiter = self._s.waiter
        skip = self._skip_preflight
        commitment = self._preflight_commitment

        self.debug(f'start transactions sending: {self._name}')

        while (self._retry_idx < RETRY_ON_FAIL) and (len(self._tx_list)):
            self._retry_idx += 1
            self._slots_behind = 0

            receipt_list = solana.send_multiple_transactions(signer, self._tx_list, waiter, skip, commitment)
            self.update_transaction_cost(receipt_list)

            success_cnt = 0
            for receipt, tx in zip(receipt_list, self._tx_list):
                receipt_parser = SolReceiptParser(receipt)
                slots_behind = receipt_parser.get_slots_behind()
                if slots_behind:
                    self._slots_behind = slots_behind
                    self._node_behind_list.append(tx)
                elif receipt_parser.check_if_blockhash_notfound():
                    self._bad_block_list.append(tx)
                elif receipt_parser.check_if_accounts_blocked():
                    self._blocked_account_list.append(tx)
                elif receipt_parser.check_if_budget_exceeded():
                    self._budget_exceeded_list.append(tx)
                    self._budget_exceeded_receipt = receipt
                elif receipt_parser.check_if_error():
                    self._unknown_error_list.append(receipt)
                else:
                    success_cnt += 1
                    self._retry_idx = 0
                    self._on_success_send(tx, receipt)

            self.debug(f'retry {self._retry_idx}, ' +
                       f'total receipts {len(receipt_list)}, ' +
                       f'success receipts {self._total_success_cnt}(+{success_cnt}), ' +
                       f'node behind {len(self._node_behind_list)}, '
                       f'bad blocks {len(self._bad_block_list)}, ' +
                       f'blocked accounts {len(self._blocked_account_list)}, ' +
                       f'budget exceeded {len(self._budget_exceeded_list)}, ' +
                       f'unknown error: {len(self._unknown_error_list)}')

            self._total_success_cnt += success_cnt
            self._on_post_send()

        if len(self._tx_list):
            raise EthereumError(message='No more retries to complete transaction!')
        return self

    def update_transaction_cost(self, receipt_list):
        if not WRITE_TRANSACTION_COST_IN_DB:
            return False
        if not hasattr(self._s, 'eth_tx'):
            return False

        for receipt in receipt_list:
            update_transaction_cost(receipt, self._s.eth_tx, reason=self._name)

    def _on_success_send(self, tx: Transaction, receipt: {}) -> bool:
        """Store the last successfully blockhash and set it in _set_tx_blockhash"""
        self._blockhash = tx.recent_blockhash
        return False

    def _on_post_send(self):
        if len(self._unknown_error_list):
            raise SolTxError(self._unknown_error_list[0])
        elif len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            time.sleep(1)
        elif len(self._budget_exceeded_list):
            raise SolTxError(self._budget_exceeded_receipt)

        if len(self._blocked_account_list):
            time.sleep(0.4)  # one block time

        # force changing of recent_blockhash if Solana doesn't accept the current one
        if len(self._bad_block_list):
            self._blockhash = None

        # resend not-accepted transactions
        self._move_txlist()

    def _set_tx_blockhash(self, tx):
        """Try to keep the branch of block history"""
        tx.recent_blockhash = self._blockhash
        tx.signatures.clear()

    def _move_txlist(self):
        full_list = self._get_full_list()
        self.clear()
        for tx in full_list:
            self._set_tx_blockhash(tx)
            self._tx_list.append(tx)
        if len(self._tx_list):
            self.debug(f' Resend Solana transactions: {len(self._tx_list)}')

    def raise_budget_exceeded(self):
        if self._budget_exceeded_receipt is not None:
            raise SolTxError(self._budget_exceeded_receipt)
        SolReceiptParser.raise_budget_exceeded()

