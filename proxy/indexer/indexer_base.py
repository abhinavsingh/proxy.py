import os
import time
import logging
import traceback
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from typing import Dict, Union

try:
    from sql_dict import SQLDict
    from trx_receipts_storage import TrxReceiptsStorage
except ImportError:
    from .sql_dict import SQLDict
    from .trx_receipts_storage import TrxReceiptsStorage


PARALLEL_REQUESTS = int(os.environ.get("PARALLEL_REQUESTS", "2"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DEVNET_HISTORY_START = "7BdwyUQ61RUZP63HABJkbW66beLk22tdXnP69KsvQBJekCPVaHoJY47Rw68b3VV1UbQNHxX3uxUSLfiJrfy2bTn"
HISTORY_START = [DEVNET_HISTORY_START]


log_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARN': logging.WARN,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'FATAL': logging.FATAL,
    'CRITICAL': logging.CRITICAL
}

class IndexerBase:
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 log_level,
                 start_slot):
        logger.setLevel(log_levels.get(log_level, logging.INFO))

        self.evm_loader_id = evm_loader_id
        self.client = Client(solana_url)
        self.transaction_receipts = TrxReceiptsStorage('transaction_receipts', log_level)
        self.last_slot = start_slot
        self.current_slot = 0
        self.counter_ = 0
        self.max_known_tx = self.transaction_receipts.max_known_trx()
        self._move_data_from_old_table()


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
                logger.warning('Exception on submitting transaction. ' +
                               f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            time.sleep(1.0)


    def process_functions(self):
        logger.debug("Start indexing")
        self.gather_unknown_transactions()


    def gather_unknown_transactions(self):
        poll_txs = set()

        minimal_tx = None
        continue_flag = True
        current_slot = self.client.get_slot(commitment="finalized")["result"]

        max_known_tx = self.max_known_tx

        counter = 0
        while (continue_flag):
            results = self._get_signatures(minimal_tx, self.max_known_tx[1])
            logger.debug("{:>3} get_signatures_for_address {}".format(counter, len(results)))
            counter += 1

            if len(results) == 0:
                logger.debug("len(results) == 0")
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
                    logger.debug(solana_signature)
                    continue_flag = False
                    break

                if not self.transaction_receipts.contains(slot, solana_signature):
                    poll_txs.add(solana_signature)

        logger.debug("start getting receipts")
        pool = ThreadPool(PARALLEL_REQUESTS)
        pool.map(self._get_tx_receipts, poll_txs)

        self.current_slot = current_slot
        self.counter_ = 0
        logger.debug(max_known_tx)
        self.max_known_tx = max_known_tx


    def _get_signatures(self, before, until):
        opts: Dict[str, Union[int, str]] = {}
        if until is not None:
            opts["until"] = until
        if before is not None:
            opts["before"] = before
        opts["commitment"] = "finalized"
        result = self.client._provider.make_request("getSignaturesForAddress", self.evm_loader_id, opts)
        return result['result']


    def _get_tx_receipts(self, solana_signature):
        # trx = None
        retry = True

        while retry:
            try:
                trx = self.client.get_confirmed_transaction(solana_signature)['result']
                self._add_trx(solana_signature, trx)
                retry = False
            except Exception as err:
                logger.debug(err)
                time.sleep(1)

        self.counter_ += 1
        if self.counter_ % 100 == 0:
            logger.debug(self.counter_)


    def _add_trx(self, solana_signature, trx):
        if trx is not None:
            add = False
            for instruction in trx['transaction']['message']['instructions']:
                if trx["transaction"]["message"]["accountKeys"][instruction["programIdIndex"]] == self.evm_loader_id:
                    add = True
            if add:
                logger.debug((trx['slot'], solana_signature))
                self.transaction_receipts.add_trx(trx['slot'], solana_signature, trx)
        else:
            logger.debug(f"trx is None {solana_signature}")

