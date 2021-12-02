import os
import time
import logging
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from typing import Dict, Union

try:
    from sql_dict import SQLDict
except ImportError:
    from .sql_dict import SQLDict


PARALLEL_REQUESTS = int(os.environ.get("PARALLEL_REQUESTS", "2"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
                 log_level):
        logger.setLevel(log_levels.get(log_level, logging.INFO))

        self.evm_loader_id = evm_loader_id
        self.client = Client(solana_url)
        self.transaction_receipts = SQLDict(tablename="known_transactions")
        self.last_slot = 0
        self.current_slot = 0
        self.transaction_order = []
        self.counter_ = 0


    def run(self):
        while (True):
            try:
                self.process_functions()
            except Exception as err:
                logger.warning("Got exception while indexing. Type(err):%s, Exception:%s", type(err), err)


    def process_functions(self):
        logger.debug("Start indexing")
        self.gather_unknown_transactions()


    def gather_unknown_transactions(self):
        poll_txs = set()
        ordered_txs = []

        minimal_tx = None
        continue_flag = True
        current_slot = self.client.get_slot(commitment="confirmed")["result"]
        maximum_slot = self.last_slot
        minimal_slot = current_slot

        counter = 0
        while (continue_flag):
            opts: Dict[str, Union[int, str]] = {}
            if minimal_tx:
                opts["before"] = minimal_tx
            opts["commitment"] = "confirmed"
            result = self.client._provider.make_request("getSignaturesForAddress", self.evm_loader_id, opts)
            logger.debug("{:>3} get_signatures_for_address {}".format(counter, len(result["result"])))
            counter += 1

            if len(result["result"]) == 0:
                logger.debug("len(result['result']) == 0")
                break

            for tx in result["result"]:
                solana_signature = tx["signature"]
                slot = tx["slot"]

                if solana_signature in HISTORY_START:
                    logger.debug(solana_signature)
                    continue_flag = False
                    break

                ordered_txs.append(solana_signature)

                if solana_signature not in self.transaction_receipts:
                    poll_txs.add(solana_signature)

                if slot < minimal_slot:
                    minimal_slot = slot
                    minimal_tx = solana_signature

                if slot > maximum_slot:
                    maximum_slot = slot

                if slot < self.last_slot:
                    continue_flag = False
                    break

        logger.debug("start getting receipts")
        pool = ThreadPool(PARALLEL_REQUESTS)
        pool.map(self.get_tx_receipts, poll_txs)

        if len(self.transaction_order):
            index = 0
            try:
                index = ordered_txs.index(self.transaction_order[0])
            except ValueError:
                self.transaction_order = ordered_txs + self.transaction_order
            else:
                self.transaction_order = ordered_txs[:index] + self.transaction_order
        else:
            self.transaction_order = ordered_txs

        self.last_slot = maximum_slot
        self.current_slot = current_slot

        self.counter_ = 0


    def get_tx_receipts(self, solana_signature):
        # trx = None
        retry = True

        while retry:
            try:
                trx = self.client.get_confirmed_transaction(solana_signature)['result']
                self.transaction_receipts[solana_signature] = trx
                retry = False
            except Exception as err:
                logger.debug(err)
                time.sleep(1)

        self.counter_ += 1
        if self.counter_ % 100 == 0:
            logger.debug(self.counter_)

        # return (solana_signature, trx)
