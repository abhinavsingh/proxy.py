import os
import time
import traceback
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from typing import Dict, Union
from logged_groups import logged_group

from ..environment import RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION
from ..environment import HISTORY_START, PARALLEL_REQUESTS, FINALIZED

try:
    from sql_dict import SQLDict
    from trx_receipts_storage import TrxReceiptsStorage
except ImportError:
    from .sql_dict import SQLDict
    from .trx_receipts_storage import TrxReceiptsStorage


@logged_group("neon.Indexer")
class IndexerBase:
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 last_slot):
        self.evm_loader_id = evm_loader_id
        self.client = Client(solana_url)
        self.transaction_receipts = TrxReceiptsStorage('transaction_receipts')
        self._move_data_from_old_table()
        self.max_known_tx = self.transaction_receipts.max_known_trx()
        self.last_slot = self._init_last_slot('receipt', last_slot)
        self.current_slot = 0
        self.counter_ = 0

    def _init_last_slot(self, name: str, last_known_slot: int):
        """
        This function allow to skip some part of history.
        - LATEST - start from the last block slot from Solana
        - CONTINUE - continue from the last parsed slot of from latest
        - NUMBER - first start from the number, then continue from last parsed slot
        """
        last_known_slot = 0 if not isinstance(last_known_slot, int) else last_known_slot
        latest_slot = self.client.get_slot(commitment=FINALIZED)["result"]
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

    def _move_data_from_old_table(self):
        if self.transaction_receipts.size() == 0:
            transaction_receipts_old = SQLDict(tablename="known_transactions")
            for signature, trx in transaction_receipts_old.iteritems():
                self._add_trx(signature, trx)

    def run(self):
        while (True):
            try:
                self.process_functions()
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning('Exception on submitting transaction. ' +
                             f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            time.sleep(1.0)

    def process_functions(self):
        self.debug("Start indexing")
        self.gather_unknown_transactions()

    def gather_unknown_transactions(self):
        poll_txs = set()

        minimal_tx = None
        continue_flag = True
        current_slot = self.client.get_slot(commitment=FINALIZED)["result"]

        max_known_tx = self.max_known_tx

        counter = 0
        while (continue_flag):
            results = self._get_signatures(minimal_tx, self.max_known_tx[1])
            self.debug("{:>3} get_signatures_for_address {}".format(counter, len(results)))
            counter += 1

            if len(results) == 0:
                self.debug("len(results) == 0")
                break

            minimal_tx = results[-1]["signature"]
            max_tx = (results[0]["slot"], results[0]["signature"])
            max_known_tx = max(max_known_tx, max_tx)

            for tx in results:
                solana_signature = tx["signature"]
                slot = tx["slot"]

                if slot < self.last_slot:
                    continue_flag = False
                    break

                if solana_signature in HISTORY_START:
                    self.debug(solana_signature)
                    continue_flag = False
                    break

                if not self.transaction_receipts.contains(slot, solana_signature):
                    poll_txs.add(solana_signature)

        self.debug("start getting receipts")
        pool = ThreadPool(PARALLEL_REQUESTS)
        pool.map(self._get_tx_receipts, poll_txs)

        self.current_slot = current_slot
        self.counter_ = 0
        self.debug(max_known_tx)
        self.max_known_tx = max_known_tx

    def _get_signatures(self, before, until):
        opts: Dict[str, Union[int, str]] = {}
        if until is not None:
            opts["until"] = until
        if before is not None:
            opts["before"] = before
        opts["commitment"] = FINALIZED
        result = self.client._provider.make_request("getSignaturesForAddress", self.evm_loader_id, opts)
        return result['result']

    def _get_tx_receipts(self, solana_signature):
        # trx = None
        retry = RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION

        while retry > 0:
            try:
                trx = self.client.get_confirmed_transaction(solana_signature)['result']
                self._add_trx(solana_signature, trx)
                retry = 0
            except Exception as err:
                self.debug(f'Exception on get_confirmed_transaction: "{err}"')
                time.sleep(1)
                retry -= 1
                if retry == 0:
                    self.error(f'Exception on get_confirmed_transaction: "{err}"')

        self.counter_ += 1
        if self.counter_ % 100 == 0:
            self.debug(self.counter_)


    def _add_trx(self, solana_signature, trx):
        if trx is not None:
            add = False
            for instruction in trx['transaction']['message']['instructions']:
                if trx["transaction"]["message"]["accountKeys"][instruction["programIdIndex"]] == self.evm_loader_id:
                    add = True
            if add:
                self.debug((trx['slot'], solana_signature))
                self.transaction_receipts.add_trx(trx['slot'], solana_signature, trx)
        else:
            self.debug(f"trx is None {solana_signature}")

