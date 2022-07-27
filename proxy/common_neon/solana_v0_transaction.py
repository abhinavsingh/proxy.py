from typing import List, Dict

from solana.transaction import Transaction
from solana.publickey import PublicKey
from solana.message import MessageHeader, CompiledInstruction

from ..common_neon.errors import AddressLookupTableError
from ..common_neon.solana_v0_message import V0Message, V0MessageArgs, MessageAddressTableLookup
from ..common_neon.solana_alt_list_filter import AddressLookupTableListFilter
from ..common_neon.solana_alt import AddressLookupTableInfo


class V0Transaction(Transaction):
    """Versioned transaction class to represent an atomic versioned transaction."""

    def __init__(self, *args, address_table_lookups: List[AddressLookupTableInfo] = None) -> None:
        super().__init__(*args)

        if not isinstance(address_table_lookups, list):
            raise AddressLookupTableError('Address table lookups should be a list')
        elif len(address_table_lookups) == 0:
            raise AddressLookupTableError('No address lookup tables')

        for alt_info in address_table_lookups:
            if not isinstance(alt_info, AddressLookupTableInfo):
                raise AddressLookupTableError(f'Bad type {type(alt_info)} for address lookup table')

        self.address_table_lookups: List[AddressLookupTableInfo] = address_table_lookups

    def compile_message(self) -> V0Message:
        legacy_msg = super().compile_message()
        alt_filter = AddressLookupTableListFilter(legacy_msg)

        rw_key_set = alt_filter.filter_rw_account_key_set()
        ro_key_set = alt_filter.filter_ro_account_key_set()

        # Account indexes must index into the list of addresses
        # constructed from the concatenation of three key lists:
        #   1) message `account_keys`
        #   2) ordered list of keys loaded from `writable` lookup table indexes
        #   3) ordered list of keys loaded from `readable` lookup table indexes

        rw_key_list: List[str] = []
        ro_key_list: List[str] = []

        # Build the lookup list in the V0 transaction
        alt_msg_list: List[MessageAddressTableLookup] = []
        for alt_info in self.address_table_lookups:
            rw_idx_list: List[int] = []
            ro_idx_list: List[int] = []
            for idx, key in enumerate(alt_info.account_key_list):
                key = str(key)
                if key in rw_key_set:
                    rw_idx_list.append(idx)
                    rw_key_list.append(key)
                    rw_key_set.discard(key)
                elif key in ro_key_set:
                    ro_idx_list.append(idx)
                    ro_key_list.append(key)
                    ro_key_set.discard(key)

            if len(rw_idx_list) == len(ro_idx_list) == 0:
                continue

            alt_msg_list.append(
                MessageAddressTableLookup(
                    account_key=alt_info.table_account,
                    writable_indexes=rw_idx_list,
                    readonly_indexes=ro_idx_list,
                )
            )

        if not len(alt_msg_list):
            raise AddressLookupTableError(f'No account lookups to include into V0Transaction')

        # Set the positions of the static transaction accounts
        signed_key_cnt = legacy_msg.header.num_required_signatures
        tx_key_list = alt_filter.tx_account_key_list
        tx_ro_unsigned_account_key_cnt = alt_filter.tx_unsigned_account_key_cnt + len(ro_key_set)
        signed_tx_key_list, ro_tx_key_list = tx_key_list[:signed_key_cnt], tx_key_list[signed_key_cnt:]

        tx_key_list = (
            signed_tx_key_list +
            # If the tx has an additional account key, which is not listed in the address_table_lookups
            #   then add it to the static part of the tx account list
            [PublicKey(key) for key in rw_key_set] +
            [PublicKey(key) for key in ro_key_set] +
            ro_tx_key_list
        )

        key_new_idx_dict: Dict[str, int] = {str(key): idx for idx, key in enumerate(tx_key_list)}
        for key in rw_key_list:
            key_new_idx_dict[key] = len(key_new_idx_dict)
        for key in ro_key_list:
            key_new_idx_dict[key] = len(key_new_idx_dict)

        # Build relations between old and new indexes
        old_new_idx_dict: Dict[int, int] = {}
        for old_idx, key in enumerate(legacy_msg.account_keys):
            key = str(key)
            new_idx = key_new_idx_dict.get(key, None)
            if new_idx is None:
                raise AddressLookupTableError(f'Account {key} does not exist in lookup accounts')
            old_new_idx_dict[old_idx] = new_idx

        # Update compiled instructions with new indexes
        new_ix_list: List[CompiledInstruction] = []
        for old_ix in legacy_msg.instructions:
            # Get the new index for the program
            old_prog_idx = old_ix.program_id_index
            new_prog_idx = old_new_idx_dict.get(old_prog_idx, None)
            if new_prog_idx is None:
                raise AddressLookupTableError(f'Program with idx {old_prog_idx} does not exist in account list')

            # Get new indexes for instruction accounts
            new_ix_acct_list: List[int] = []
            for old_idx in old_ix.accounts:
                new_idx = old_new_idx_dict.get(old_idx, None)
                if new_idx is None:
                    raise AddressLookupTableError(f'Account with idx {old_idx} does not exist in account list')
                new_ix_acct_list.append(new_idx)

            new_ix_list.append(
                CompiledInstruction(
                    program_id_index=new_prog_idx,
                    data=old_ix.data,
                    accounts=new_ix_acct_list
                )
            )

        return V0Message(
            V0MessageArgs(
                header=MessageHeader(
                    num_required_signatures=legacy_msg.header.num_required_signatures,
                    num_readonly_signed_accounts=legacy_msg.header.num_readonly_signed_accounts,
                    num_readonly_unsigned_accounts=tx_ro_unsigned_account_key_cnt
                ),
                account_keys=[str(key) for key in tx_key_list],
                instructions=new_ix_list,
                recent_blockhash=legacy_msg.recent_blockhash,
                address_table_lookups=alt_msg_list
            )
        )
