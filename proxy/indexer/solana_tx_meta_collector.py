from __future__ import annotations

from multiprocessing.dummy import Pool as ThreadPool

from logged_groups import logged_group
from typing import Optional, Dict, Union, Iterator, List, Any
from abc import ABC, abstractmethod

from .solana_signatures_db import SolSigsDB
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.environment_data import INDEXER_PARALLEL_REQUEST_COUNT, INDEXER_POLL_COUNT
from ..common_neon.environment_data import FINALIZED, CONFIRMED
from ..common_neon.solana_neon_tx_receipt import SolTxMetaInfo, SolTxSigSlotInfo


class SolHistoryNotFound(RuntimeError):
    def __init__(self, error: str):
        super().__init__(error)


@logged_group("neon.Indexer")
class SolTxMetaDict:
    def __init__(self):
        self._tx_meta_dict: Dict[SolTxSigSlotInfo, SolTxMetaInfo] = {}

    def has_sig(self, sig_slot: SolTxSigSlotInfo) -> bool:
        return sig_slot in self._tx_meta_dict

    def add(self, sig_slot: SolTxSigSlotInfo, tx_meta: Dict[str, Any]) -> None:
        if tx_meta is None:
            raise SolHistoryNotFound(f'Solana receipt {sig_slot} not found')

        block_slot = tx_meta['slot']
        sol_sig = tx_meta['transaction']['signatures'][0]
        if block_slot != sig_slot.block_slot:
            raise SolHistoryNotFound(f'Solana receipt {sig_slot} on another history branch: {sol_sig}:{block_slot}')
        self._tx_meta_dict[sig_slot] = SolTxMetaInfo.from_response(sig_slot, tx_meta)

    def get(self, sig_slot: SolTxSigSlotInfo) -> Optional[SolTxMetaInfo]:
        tx_meta = self._tx_meta_dict.get(sig_slot, None)
        if tx_meta is None:
            raise SolHistoryNotFound(f'no Solana receipt for the signature: {sig_slot}')
        return tx_meta

    def pop(self, sig_slot: SolTxSigSlotInfo) -> Optional[SolTxMetaInfo]:
        return self._tx_meta_dict.pop(sig_slot, None)

    def keys(self) -> List[SolTxSigSlotInfo]:
        return list(self._tx_meta_dict.keys())


@logged_group("neon.Indexer")
class SolTxMetaCollector(ABC):
    def __init__(self, tx_meta_dict: SolTxMetaDict, solana: SolanaInteractor, commitment: str, is_finalized: bool):
        self._solana = solana
        self._commitment = commitment
        self._is_finalized = is_finalized
        self._tx_meta_dict = tx_meta_dict
        self._thread_pool = ThreadPool(INDEXER_PARALLEL_REQUEST_COUNT)

    @property
    def commitment(self) -> str:
        return self._commitment

    @property
    def is_finalized(self) -> bool:
        return self._is_finalized

    @abstractmethod
    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        pass

    def _iter_tx_meta(self, sig_slot_list: List[SolTxSigSlotInfo]) -> Iterator[SolTxMetaInfo]:
        group_len = 20
        flat_len = len(sig_slot_list)
        grouped_sig_slot_list = [sig_slot_list[i:(i + group_len)] for i in range(0, flat_len, group_len)]
        self._gather_tx_meta_dict(grouped_sig_slot_list)
        for sig_slot in reversed(sig_slot_list):
            yield self._tx_meta_dict.get(sig_slot)

    def _gather_tx_meta_dict(self, grouped_sig_slot_list: List[List[SolTxSigSlotInfo]]) -> None:
        if len(grouped_sig_slot_list) > 1:
            self._thread_pool.map(self._request_tx_meta_list, grouped_sig_slot_list)
        elif len(grouped_sig_slot_list) > 0:
            self._request_tx_meta_list(grouped_sig_slot_list[0])

    def _request_tx_meta_list(self, sig_slot_list: List[SolTxSigSlotInfo]) -> None:
        sig_list = [sig_slot.sol_sig for sig_slot in sig_slot_list if not self._tx_meta_dict.has_sig(sig_slot)]
        if len(sig_list) == 0:
            return

        meta_list = self._solana.get_multiple_receipts(sig_list, commitment=self._commitment)
        for sig_slot, tx_meta in zip(sig_slot_list, meta_list):
            self._tx_meta_dict.add(sig_slot, tx_meta)

    def _iter_sig_slot(self, start_sig: Optional[str], start_slot: int, stop_slot: int) -> Iterator[SolTxSigSlotInfo]:
        response_list_len = 1
        while response_list_len:
            response_list = self._request_sig_info_list(start_sig, INDEXER_POLL_COUNT)
            response_list_len = len(response_list)
            if response_list_len == 0:
                return
            start_sig = response_list[-1]["signature"]

            for response in response_list:
                block_slot = response['slot']
                if block_slot > start_slot:
                    continue
                elif block_slot < stop_slot:
                    return

                yield SolTxSigSlotInfo(block_slot=block_slot, sol_sig=response['signature'])

    def _request_sig_info_list(self, start_sig: Optional[str], limit: int) -> List[Dict[str, Union[int, str]]]:
        response = self._solana.get_signatures_for_address(start_sig, limit, self._commitment)
        error = response.get('error')
        if error:
            self.warning(f'fail to get solana signatures: {error}')

        return response.get('result', [])


@logged_group("neon.Indexer")
class FinalizedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, tx_meta_dict: SolTxMetaDict, solana: SolanaInteractor, stop_slot: int):
        super().__init__(tx_meta_dict, solana, commitment=FINALIZED, is_finalized=True)
        self.debug(f'Finalized commitment: {self._commitment}')
        self._sigs_db = SolSigsDB()
        self._stop_slot = stop_slot
        self._sig_cnt = 0
        self._last_info: Optional[SolTxMetaInfo] = None

    @property
    def last_block_slot(self) -> int:
        return self._stop_slot

    def _build_checkpoint_list(self, start_slot: int) -> None:
        max_sig = self._sigs_db.get_max_sig()
        stop_slot = max(max_sig.block_slot, self._stop_slot) if max_sig else self._stop_slot
        self._stop_slot = stop_slot
        for info in self._iter_sig_slot(None, start_slot, stop_slot):
            self._save_checkpoint(info)

    def _save_checkpoint(self, info: SolTxSigSlotInfo, cnt: int = 1) -> None:
        self._sig_cnt += cnt
        if self._sig_cnt < INDEXER_POLL_COUNT:
            return
        elif self._last_info is None:
            self._last_info = info
        elif self._last_info.block_slot != info.block_slot:
            self.debug(f'save checkpoint: {info}: {self._sig_cnt}')
            self._sigs_db.add_sig(info)
            self._reset_checkpoint_cache()

    def _reset_checkpoint_cache(self) -> None:
        self._last_info = None
        self._sig_cnt = 0

    def _iter_sig_slot_list(self, start_slot: int, is_long_list: bool) -> Iterator[List[SolTxSigSlotInfo]]:
        start_sig: Optional[str] = ''
        next_info: Optional[SolTxSigSlotInfo] = None
        while start_sig is not None:
            start_sig = None
            if is_long_list:
                next_info = self._sigs_db.get_next_sig(self._stop_slot)
                if next_info:
                    start_sig = next_info.sol_sig

            sig_slot_list = list(self._iter_sig_slot(start_sig, start_slot, self._stop_slot))
            sig_slot_list_len = len(sig_slot_list)
            if sig_slot_list_len == 0:
                if next_info is not None:
                    self._stop_slot = next_info.block_slot + 1
                    continue
                return

            if next_info is None:
                self._stop_slot = sig_slot_list[0].block_slot + 1
            else:
                self._stop_slot = next_info.block_slot + 1

            if not is_long_list:
                self._save_checkpoint(sig_slot_list[0], sig_slot_list_len)
            yield sig_slot_list

    def _prune_tx_meta_dict(self) -> None:
        for sig_slot in list(self._tx_meta_dict.keys()):
            if sig_slot.block_slot < self._stop_slot:
                self._tx_meta_dict.pop(sig_slot)

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        if start_slot < stop_slot:
            return

        is_long_list = (start_slot - stop_slot) > 10
        if is_long_list:
            self._build_checkpoint_list(start_slot)

        self._stop_slot = stop_slot
        for sig_slot_list in self._iter_sig_slot_list(start_slot, is_long_list):
            for tx_meta in self._iter_tx_meta(sig_slot_list):
                self._tx_meta_dict.pop(tx_meta.ident)
                yield tx_meta


@logged_group("neon.Indexer")
class ConfirmedSolTxMetaCollector(SolTxMetaCollector):
    def __init__(self, tx_meta_dict: SolTxMetaDict, solana: SolanaInteractor):
        super().__init__(tx_meta_dict, solana, commitment=CONFIRMED, is_finalized=False)
        self.debug(f'Confirmed commitment: {self._commitment}')

    def iter_tx_meta(self, start_slot: int, stop_slot: int) -> Iterator[SolTxMetaInfo]:
        assert start_slot >= stop_slot

        sig_slot_list = list(self._iter_sig_slot(None, start_slot, stop_slot))
        return self._iter_tx_meta(sig_slot_list)
