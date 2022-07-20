from typing import List

from solana.transaction import Transaction, AccountMeta
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.solana_interactor import SolanaInteractor, StorageAccountInfo
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..common_neon.solana_v0_transaction import V0Transaction
from ..common_neon.solana_alt import AddressLookupTableInfo
from ..common_neon.solana_alt_builder import AddressLookupTableTxBuilder, AddressLookupTableTxList
from ..common_neon.solana_alt_close_queue import AddressLookupTableCloseQueue


class CancelTxExecutor:
    def __init__(self, solana: SolanaInteractor, signer: SolanaAccount) -> None:
        self._builder = NeonIxBuilder(signer.public_key())
        self._solana = solana
        self._signer = signer

        self._alt_close_queue = AddressLookupTableCloseQueue(self._solana)
        self._alt_builder = AddressLookupTableTxBuilder(solana, self._builder, signer, self._alt_close_queue)
        self._alt_tx_list = AddressLookupTableTxList()
        self._alt_info_list: List[AddressLookupTableInfo] = []
        self._cancel_tx_list: List[Transaction] = []

    def add_blocked_storage_account(self, storage_info: StorageAccountInfo) -> None:
        if len(storage_info.account_list) >= self._alt_builder.TX_ACCOUNT_CNT:
            tx = self._build_alt_cancel_tx(storage_info)
        else:
            tx = self._build_cancel_tx(storage_info)
        self._cancel_tx_list.append(tx)

    def _build_cancel_tx(self, storage_info: StorageAccountInfo) -> Transaction:
        key_list: List[AccountMeta] = []
        for is_writable, acct in storage_info.account_list:
            key_list.append(AccountMeta(pubkey=PublicKey(acct), is_signer=False, is_writable=is_writable))

        return TransactionWithComputeBudget().add(
            self._builder.make_cancel_instruction(
                storage_account=storage_info.storage_account,
                nonce=storage_info.nonce,
                cancel_key_list=key_list
            )
        )

    def _build_alt_cancel_tx(self, storage_info: StorageAccountInfo) -> Transaction:
        legacy_tx = self._build_cancel_tx(storage_info)
        alt_info = self._alt_builder.build_alt_info(legacy_tx)
        alt_tx_list = self._alt_builder.build_alt_tx_list(alt_info)

        self._alt_info_list.append(alt_info)
        self._alt_tx_list.append(alt_tx_list)

        return V0Transaction(address_table_lookups=[alt_info]).add(legacy_tx)

    def execute_tx_list(self) -> List[str]:
        sig_list: List[str] = []

        if not len(self._cancel_tx_list):
            return sig_list

        # Prepare Address Lookup Tables
        if len(self._alt_tx_list):
            sig_list += self._alt_builder.prep_alt_list(self._alt_tx_list)

            # Update lookups from Solana
            self._alt_builder.update_alt_info_list(self._alt_info_list)

        tx_list_name = f'Cancel({len(self._cancel_tx_list)})'
        tx_list = self._cancel_tx_list

        # Close old Address Lookup Tables
        alt_tx_list = self._alt_close_queue.pop_tx_list(self._signer.public_key())
        if len(alt_tx_list):
            tx_list_name = ' + '.join([tx_list_name, f'CloseLookupTable({len(alt_tx_list)})'])
            tx_list.extend(alt_tx_list)

        tx_sender = SolTxListSender(self._solana, self._signer)
        tx_sender.send(tx_list_name, tx_list)
        sig_list += tx_sender.success_sig_list

        if len(self._alt_tx_list):
            # Deactivate Address Lookup Tables
            sig_list += self._alt_builder.done_alt_list(self._alt_tx_list)

        return sig_list

    def clear(self) -> None:
        self._alt_info_list.clear()
        self._alt_tx_list.clear()
        self._cancel_tx_list.clear()
