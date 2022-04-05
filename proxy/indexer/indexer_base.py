import os
import time
import traceback
from multiprocessing.dummy import Pool as ThreadPool
from logged_groups import logged_group
from typing import Optional

from .trx_receipts_storage import TxReceiptsStorage
from .utils import MetricsToLogBuff
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.sql_dict import SQLDict

from ..environment import RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION
from ..environment import HISTORY_START, PARALLEL_REQUESTS, FINALIZED, EVM_LOADER_ID


@logged_group("neon.Indexer")
class IndexerBase:
    def __init__(self,
                 solana: SolanaInteractor,
                 last_slot: int):
        self.solana = solana
        self.transaction_receipts = TxReceiptsStorage('solana_transaction_receipts')
        self.last_slot = self._init_last_slot('receipt', last_slot)
        self.current_slot = 0
        self.counter_ = 0
        self.count_log = MetricsToLogBuff()
        self._constants = SQLDict(tablename="constants")
        self._maximum_tx = self._get_maximum_tx()

    def _get_maximum_tx(self) -> str:
        if "maximum_tx" in self._constants:
            return self._constants["maximum_tx"]
        return ""

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

    def gather_unknown_transactions(self):
        start_time = time.time()
        poll_txs = []

        minimal_tx = None
        maximum_tx = None
        maximum_slot = None
        continue_flag = True
        current_slot = self.solana.get_slot(commitment=FINALIZED)["result"]

        counter = 0
        gathered_signatures = 0
        while continue_flag:
            results = self._get_signatures(minimal_tx, 1000)
            len_results = len(results)
            if len_results == 0:
                break

            minimal_tx = results[-1]["signature"]
            if maximum_tx is None:
                tx = results[0]
                maximum_tx = tx["signature"]
                maximum_slot = tx["slot"]

            gathered_signatures += len_results
            counter += 1

            tx_idx = 0
            prev_slot = 0

            for tx in results:
                sol_sign = tx["signature"]
                slot = tx["slot"]

                if slot != prev_slot:
                    tx_idx = 0
                prev_slot = slot

                if slot < self.last_slot:
                    continue_flag = False
                    break

                if sol_sign in [HISTORY_START, self._maximum_tx]:
                    continue_flag = False
                    break

                if not self.transaction_receipts.contains(slot, sol_sign):
                    poll_txs.append((sol_sign, slot, tx_idx))
                tx_idx += 1

        pool = ThreadPool(PARALLEL_REQUESTS)
        pool.map(self._get_tx_receipts, poll_txs)

        self.current_slot = current_slot
        self.counter_ = 0
        self._set_maximum_tx(maximum_tx)

        get_history_ms = (time.time() - start_time) * 1000  # convert this into milliseconds
        self.count_log.print(
            self.debug,
            list_params={"get_history_ms": get_history_ms, "gathered_signatures": gathered_signatures, "counter": counter},
            latest_params={"maximum_tx": maximum_tx, "maximum_slot": maximum_slot}
        )

    def _get_signatures(self, before: Optional[str], limit: int) -> []:
        response = self.solana.get_signatures_for_address(before, limit, FINALIZED)
        error = response.get('error')
        result = response.get('result', [])
        if error:
            self.warning(f'Fail to get signatures: {error}')
        return result

    def _get_tx_receipts(self, param):
        # tx = None
        retry = RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION

        (sol_sign, slot, tx_idx) = param
        while retry > 0:
            try:
                tx = self.solana.get_confirmed_transaction(sol_sign)['result']
                self._add_tx(sol_sign, tx, slot, tx_idx)
                retry = 0
            except Exception as err:
                self.debug(f'Exception on get_confirmed_transaction: "{err}"')
                time.sleep(1)
                retry -= 1
                if retry == 0:
                    self.error(f'Exception on get_confirmed_transaction: "{err}"')

        self.counter_ += 1
        if self.counter_ % 100 == 0:
            self.debug(f"Acquired {self.counter_} receipts")

    def _add_tx(self, sol_sign, tx, slot, tx_idx):
        if tx is not None:
            add = False
            msg = tx['transaction']['message']
            for instruction in msg['instructions']:
                if msg["accountKeys"][instruction["programIdIndex"]] == EVM_LOADER_ID:
                    add = True
            if add:
                self.debug((slot, tx_idx, sol_sign))
                self.transaction_receipts.add_tx(slot, tx_idx, sol_sign, tx)
        else:
            self.debug(f"trx is None {sol_sign}")

