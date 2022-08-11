from __future__ import annotations

import time

from typing import Optional, List

from solana.account import Account as SolanaAccount
from solana.transaction import Transaction

from ..common_neon.errors import AddressLookupTableError
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.solana_alt import AddressLookupTableInfo
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.solana_tx_list_sender import SolTxListInfo


class AddressLookupTableTxSet:
    def __init__(self, create_alt_tx_list: Optional[List[Transaction]] = None,
                 extend_alt_tx_list: Optional[List[Transaction]] = None,
                 deactivate_alt_tx_list: Optional[List[Transaction]] = None) -> None:
        self.create_alt_tx_list = create_alt_tx_list if create_alt_tx_list is not None else []
        self.extend_alt_tx_list = extend_alt_tx_list if extend_alt_tx_list is not None else []
        self.deactivate_alt_tx_list = deactivate_alt_tx_list if deactivate_alt_tx_list is not None else []

    def extend(self, tx_list: AddressLookupTableTxSet) -> AddressLookupTableTxSet:
        self.create_alt_tx_list.extend(tx_list.create_alt_tx_list)
        self.extend_alt_tx_list.extend(tx_list.extend_alt_tx_list)
        self.deactivate_alt_tx_list.extend(tx_list.deactivate_alt_tx_list)
        return self

    def __len__(self) -> int:
        return len(self.create_alt_tx_list) + len(self.extend_alt_tx_list) + len(self.deactivate_alt_tx_list)

    def clear(self) -> None:
        self.create_alt_tx_list.clear()
        self.extend_alt_tx_list.clear()
        self.deactivate_alt_tx_list.clear()


class AddressLookupTableTxBuilder:
    TX_ACCOUNT_CNT = 30

    def __init__(self, solana: SolanaInteractor, builder: NeonIxBuilder, signer: SolanaAccount,
                 alt_close_queue: AddressLookupTableCloseQueue) -> None:
        self._solana = solana
        self._builder = builder
        self._signer = signer
        self._alt_close_queue = alt_close_queue
        self._recent_block_slot: Optional[int] = None

    def _get_recent_block_slot(self) -> int:
        while True:
            recent_block_slot = self._solana.get_recent_blockslot('finalized')
            if recent_block_slot == self._recent_block_slot:
                time.sleep(0.1)  # To make unique address for Address Lookup Table
                continue
            self._recent_block_slot = recent_block_slot
            return recent_block_slot

    def build_alt_info(self, legacy_tx: Transaction) -> AddressLookupTableInfo:
        recent_block_slot = self._get_recent_block_slot()
        signer_key = self._signer.public_key()
        acct, nonce = AddressLookupTableInfo.derive_lookup_table_address(signer_key, recent_block_slot)
        alt_info = AddressLookupTableInfo(acct, recent_block_slot, nonce)
        alt_info.init_from_legacy_tx(legacy_tx)
        return alt_info

    def build_alt_tx_set(self, alt_info: AddressLookupTableInfo) -> AddressLookupTableTxSet:
        # Tx to create an Account Lookup Table
        create_alt_tx = Transaction().add(self._builder.make_create_lookup_table_instruction(
            alt_info.table_account, alt_info.recent_block_slot, alt_info.nonce
        ))

        # List of tx to extend the Account Lookup Table
        acct_list = alt_info.account_key_list

        extend_alt_tx_list: List[Transaction] = []
        while len(acct_list):
            acct_list_part, acct_list = acct_list[:self.TX_ACCOUNT_CNT], acct_list[self.TX_ACCOUNT_CNT:]
            tx = Transaction().add(self._builder.make_extend_lookup_table_instruction(
                alt_info.table_account, acct_list_part
            ))
            extend_alt_tx_list.append(tx)

        deactivate_alt_tx = Transaction().add(self._builder.make_deactivate_lookup_table_instruction(
            alt_info.table_account
        ))

        # If list of accounts is small, including of first extend-tx into create-tx will decrease time of tx execution
        create_alt_tx.add(extend_alt_tx_list[0])
        extend_alt_tx_list = extend_alt_tx_list[1:]

        return AddressLookupTableTxSet(
            create_alt_tx_list=[create_alt_tx],
            extend_alt_tx_list=extend_alt_tx_list,
            deactivate_alt_tx_list=[deactivate_alt_tx]
        )

    @staticmethod
    def build_prep_alt_list(alt_tx_set: AddressLookupTableTxSet) -> List[SolTxListInfo]:
        tx_list_info_list: List[SolTxListInfo] = []

        tx_list_info = SolTxListInfo(
            name_list=['CreateLookupTable:ExtendLookupTable' for _ in alt_tx_set.create_alt_tx_list],
            tx_list= alt_tx_set.create_alt_tx_list
        )
        tx_list_info_list.append(tx_list_info)

        if len(alt_tx_set.extend_alt_tx_list) > 0:
            tx_list_info = SolTxListInfo(
                name_list=['ExtendLookupTable' for _ in alt_tx_set.extend_alt_tx_list],
                tx_list=alt_tx_set.extend_alt_tx_list
            )
            tx_list_info_list.append(tx_list_info)

        return tx_list_info_list

    def update_alt_info_list(self, alt_info_list: List[AddressLookupTableInfo]) -> None:
        self._alt_close_queue.push_list(self._signer.public_key(), [a.table_account for a in alt_info_list])

        # Accounts in Account Lookup Table can be reordered
        for alt_info in alt_info_list:
            alt_acct_info = self._solana.get_account_lookup_table_info(alt_info.table_account)
            if alt_acct_info is None:
                raise AddressLookupTableError(f'Cannot read lookup table {str(alt_info.table_account)}')
            alt_info.update_from_account(alt_acct_info)

    @staticmethod
    def build_done_alt_tx_set(alt_tx_set: AddressLookupTableTxSet) -> List[SolTxListInfo]:
        tx_list_info = SolTxListInfo(
            name_list=['DeactivateLookupTable' for _ in alt_tx_set.deactivate_alt_tx_list],
            tx_list=alt_tx_set.deactivate_alt_tx_list
        )
        return [tx_list_info]
