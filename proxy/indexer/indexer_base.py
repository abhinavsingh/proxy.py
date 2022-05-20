import os
import time
import traceback
from multiprocessing.dummy import Pool as ThreadPool
from logged_groups import logged_group
from typing import Dict, List, Optional, Tuple, Union

from .solana_signatures_db import SolanaSignatures
from .utils import MetricsToLogBuff
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.sql_dict import SQLDict

from ..environment import INDEXER_POLL_COUNT, RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION
from ..environment import HISTORY_START, PARALLEL_REQUESTS, FINALIZED, EVM_LOADER_ID


@logged_group("neon.Indexer")
class IndexerBase:
    def __init__(self,
                 solana: SolanaInteractor,
                 last_slot: int):
        self.solana = solana
        self.solana_signatures = SolanaSignatures()
        self.last_slot = self._init_last_slot('receipt', last_slot)
        self.current_slot = 0
        self.counter_ = 0
        self.count_log = MetricsToLogBuff()
        self._constants = SQLDict(tablename="constants")
        self._maximum_tx = self._get_maximum_tx()
        self._tx_receipts = {}

    def _get_maximum_tx(self) -> str:
        if "maximum_tx" in self._constants:
            return self._constants["maximum_tx"]
        return HISTORY_START

    def _set_maximum_tx(self, tx: str):
        self._maximum_tx = tx
        self._constants["maximum_tx"] = tx

    def _init_last_slot(self, name: str, last_known_slot: int):
        """
        This function allow to skip some part of history.
        - LATEST - start from the last block slot from Solana
        - CONTINUE - continue from the last parsed slot of from latest
        - NUMBER - first start from the number, then continue from last parsed slot
        """
        last_known_slot = 0 if not isinstance(last_known_slot, int) else last_known_slot
        latest_slot = self.solana.get_slot(FINALIZED)["result"]
        start_int_slot = 0
        name = f'{name} slot'

        START_SLOT = os.environ.get('START_SLOT', 0)
        start_slot = START_SLOT
        if start_slot not in ['CONTINUE', 'LATEST']:
            try:
                start_int_slot = min(int(start_slot), latest_slot)
            except Exception:
                start_int_slot = 0

        if start_slot == 'CONTINUE':
            if last_known_slot > 0:
                self.info(f'START_SLOT={START_SLOT}: started the {name} from previous run {last_known_slot}')
                return last_known_slot
            else:
                self.info(f'START_SLOT={START_SLOT}: forced the {name} from the latest Solana slot')
                start_slot = 'LATEST'

        if start_slot == 'LATEST':
            self.info(f'START_SLOT={START_SLOT}: started the {name} from the latest Solana slot {latest_slot}')
            return latest_slot

        if start_int_slot < last_known_slot:
            self.info(f'START_SLOT={START_SLOT}: started the {name} from previous run, ' +
                      f'because {start_int_slot} < {last_known_slot}')
            return last_known_slot

        self.info(f'START_SLOT={START_SLOT}: started the {name} from {start_int_slot}')
        return start_int_slot

    def run(self):
        while True:
            try:
                self.process_functions()
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning('Exception on transactions processing. ' +
                             f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            time.sleep(1.0)

    def process_functions(self):
        self.gather_unknown_transactions()

    def get_tx_receipts(self, stop_slot=None):
        signatures = self.gather_unknown_transactions()
        self.debug(f'{len(signatures)}')

        poll_txs = []
        tx_list = []
        for signature, _ in reversed(signatures):
            if signature not in self._tx_receipts:
                tx_list.append(signature)
                if len(tx_list) >= 20:
                    poll_txs.append(tx_list)
                    tx_list = []
        if len(tx_list) > 0:
            poll_txs.append(tx_list)
        self._get_txs(poll_txs)

        max_tx = self._maximum_tx
        remove_signatures: List[str] = []
        for signature, _ in reversed(signatures):
            if signature not in self._tx_receipts:
                self.error(f'{signature} receipt not found')
                continue

            tx = self._tx_receipts[signature]
            slot = tx['slot']
            if stop_slot and slot > stop_slot:
                break
            yield (slot, signature, tx)

            remove_signatures.append(signature)
            del self._tx_receipts[signature]
            max_tx = signature

        self.solana_signatures.remove_signature(remove_signatures)
        self._set_maximum_tx(max_tx)
        self._clear_tx_receipts()

    def gather_unknown_transactions(self):
        minimal_tx = self.solana_signatures.get_minimal_tx()
        continue_flag = True
        counter = 0
        gathered_signatures = 0
        tx_list = []
        while continue_flag:
            results = self._get_signatures(minimal_tx, INDEXER_POLL_COUNT)
            len_results = len(results)
            if len_results == 0:
                break

            minimal_tx = results[-1]["signature"]

            gathered_signatures += len_results
            counter += 1

            for tx in results:
                sol_sign = tx["signature"]
                slot = tx["slot"]

                if sol_sign == self._maximum_tx:
                    continue_flag = False
                    break

                if slot < self.last_slot:
                    continue_flag = False
                    break

                if len(tx_list) >= INDEXER_POLL_COUNT:
                    self.solana_signatures.add_signature(tx_list[0][0], tx_list[0][1])
                    tx_list = []

                tx_list.append((sol_sign, slot))

        return tx_list


    def _get_signatures(self, before: Optional[str], limit: int) -> List[Dict[str, Union[int, str]]]:
        response = self.solana.get_signatures_for_address(before, limit, FINALIZED)
        error = response.get('error')
        result = response.get('result', [])
        if error:
            self.warning(f'Fail to get signatures: {error}')
        return result

    def _get_txs(self, poll_txs: List[List[str]]) -> None:
        if len(poll_txs) > 1:
            pool = ThreadPool(min(PARALLEL_REQUESTS, len(poll_txs)))
            pool.map(self._get_tx_receipts, poll_txs)
            poll_txs.clear()
        else:
            if len(poll_txs) > 0:
                self._get_tx_receipts(poll_txs[0])

    def _get_tx_receipts(self, sign_list: List[str]) -> None:
        if len(sign_list) == 0:
            return

        retry = RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION
        while retry > 0:
            try:
                tx_list = self.solana.get_multiple_receipts(sign_list)
                for sol_sign, tx in zip(sign_list, tx_list):
                    self._add_tx(sol_sign, tx)
                retry = 0
            except Exception as err:
                retry -= 1
                if retry == 0:
                    self.error(f'Fail to get solana receipts: "{err}"')
                else:
                    self.debug(f'Fail to get solana receipts: "{err}"')
                    time.sleep(3)

    def _add_tx(self, sol_sign, tx):
        if tx is not None:
            slot = tx['slot']
            self.debug(f'{(slot, sol_sign)}')
            self._tx_receipts[sol_sign] = tx
        else:
            self.debug(f"trx is None {sol_sign}")

    def _clear_tx_receipts(self):
        self.counter_ += 1
        if self.counter_ > 1000:
            self._tx_receipts = {}
            self.counter_ = 0
