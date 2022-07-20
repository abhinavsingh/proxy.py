from typing import Set, List, Tuple

from solana.message import Message
from solana.publickey import PublicKey

from ..common_neon.errors import AddressLookupTableError


class AddressLookupTableListFilter:
    MAX_REQUIRED_SIG_CNT = 19
    MAX_TX_ACCOUNT_CNT = 27
    MAX_ACCOUNT_CNT = 255

    def __init__(self, legacy_msg: Message) -> None:
        self._msg = legacy_msg
        self._validate_legacy_msg()
        tx_key_set, tx_unsigned_key_cnt = self._filter_tx_acct_key_set()
        self._tx_acct_key_set: Set[str] = tx_key_set
        self._tx_unsigned_acct_key_cnt = tx_unsigned_key_cnt
        self._tx_acct_key_list: List[PublicKey] = self._filter_tx_acct_key_list()

    @property
    def tx_unsigned_account_key_cnt(self):
        return self._tx_unsigned_acct_key_cnt

    @property
    def tx_account_key_list(self) -> List[PublicKey]:
        return self._tx_acct_key_list

    @property
    def len_tx_account_key_list(self) -> int:
        return len(self._tx_acct_key_list)

    def _validate_legacy_msg(self) -> None:
        if self._msg.header.num_required_signatures > self.MAX_REQUIRED_SIG_CNT:
            raise AddressLookupTableError(
                f'Too big number {self._msg.header.num_required_signatures} of signed accounts for a V0Transaction'
            )
        elif len(self._msg.account_keys) > self.MAX_ACCOUNT_CNT:
            raise AddressLookupTableError(
                f'Too big number {len(self._msg.account_keys)} of accounts for a V0Transaction'
            )

    def _filter_tx_acct_key_set(self) -> Tuple[Set[str], int]:
        acct_key_list = self._msg.account_keys

        # required accounts should be included into the transaction
        required_key_list: List[str] = [str(key) for key in acct_key_list[:self._msg.header.num_required_signatures]]

        # programs should be included into the transaction
        prog_key_list: List[str] = list(set([str(acct_key_list[ix.program_id_index]) for ix in self._msg.instructions]))

        # the result set of accounts in the static part of a transaction
        tx_acct_key_set = set(required_key_list + prog_key_list)
        if not len(tx_acct_key_set):
            raise AddressLookupTableError('Zero number of static transaction accounts')
        elif len(tx_acct_key_set) != len(required_key_list) + len(prog_key_list):
            raise AddressLookupTableError('Transaction uses signature from a program?')
        elif len(tx_acct_key_set) > self.MAX_TX_ACCOUNT_CNT:
            raise AddressLookupTableError(
                'Too big number of transactions account keys: ' +
                f'{len(tx_acct_key_set)} > {self.MAX_TX_ACCOUNT_CNT}'
            )

        return tx_acct_key_set, len(prog_key_list)

    def _filter_tx_acct_key_list(self) -> List[PublicKey]:
        assert len(self._tx_acct_key_set)

        # Returns the list in the order from the tx, because keys is are already ordered in the tx
        return [key for key in self._msg.account_keys if str(key) in self._tx_acct_key_set]

    def filter_alt_account_key_set(self) -> Set[str]:
        assert len(self._tx_acct_key_set)

        # All other accounts can be included into a lookup table
        acct_key_list = self._msg.account_keys[self._msg.header.num_required_signatures:]
        alt_acct_key_set = set([str(key) for key in acct_key_list if str(key) not in self._tx_acct_key_set])

        if len(alt_acct_key_set) + len(self._tx_acct_key_set) != len(self._msg.account_keys):
            raise AddressLookupTableError('Found duplicates in the transaction account list')

        return alt_acct_key_set

    def _get_start_ro_key_idx(self) -> int:
        key_list_len = len(self._msg.account_keys)
        return key_list_len - self._msg.header.num_readonly_unsigned_accounts

    def filter_ro_account_key_set(self) -> Set[str]:
        assert len(self._tx_acct_key_set)

        start_ro_idx = self._get_start_ro_key_idx()
        ro_acct_key_list = self._msg.account_keys[start_ro_idx:]
        ro_acct_key_set = set([str(key) for key in ro_acct_key_list if str(key) not in self._tx_acct_key_set])
        return ro_acct_key_set

    def filter_rw_account_key_set(self) -> Set[str]:
        assert len(self._tx_acct_key_set)

        start_ro_idx = self._get_start_ro_key_idx()
        rw_acct_key_list = self._msg.account_keys[self._msg.header.num_required_signatures:start_ro_idx]
        rw_acct_key_set = set([str(key) for key in rw_acct_key_list if str(key) not in self._tx_acct_key_set])
        return rw_acct_key_set
