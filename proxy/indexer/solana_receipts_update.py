import base58
import rlp
import json
import os
import time
import logging
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from sqlite_key_value import KeyValueStore
from utils import check_error, get_trx_results, get_trx_receipts


solana_url = os.environ.get("SOLANA_URL", "https://api.devnet.solana.com")
evm_loader_id = os.environ.get("EVM_LOADER", "eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU")

logger = logging.getLogger(__name__)


class HolderStruct:
    def __init__(self, storage_account):
        self.storage_account = storage_account
        self.data = bytearray(128*1024)
        self.count_written = 0
        self.max_written = 0


class ContinueStruct:
    def __init__(self, signature, logs, status, gas_used, return_value, slot):
        self.signatures = [signature]
        self.logs = logs
        self.status = status
        self.gas_used = gas_used
        self.return_value = return_value
        self.slot = slot


class Indexer:
    def __init__(self):
        self.client = Client(solana_url)
        self.transaction_receipts = KeyValueStore("known_transactions")
        self.ethereum_trx = KeyValueStore("ethereum_transactions")
        self.eth_sol_trx = KeyValueStore("ethereum_solana_transactions")
        self.sol_eth_trx = KeyValueStore("solana_ethereum_transactions")
        self.last_slot = 0
        self.transaction_order = []

    def run(self):
        while (True):
            for key in self.ethereum_trx.iterkeys():
                logger.debug("known transaction {}".format(key))
            # try:
            logger.debug("Start indexing")

            self.gather_unknown_transactions()

            # do indexation
            self.process_receipts()

            #     pass
            # except Exception as err:
            #     logger.debug("Got exception while indexing. Type(err):%s, Exception:%s", type(err), err)
            time.sleep(1)


    def gather_unknown_transactions(self):
        poll_txs = set()
        ordered_txs = []

        minimal_tx = None
        continue_flag = True
        minimal_slot = self.client.get_slot()["result"]
        maximum_slot = self.last_slot

        counter = 0
        while (continue_flag):
            result = self.client.get_signatures_for_address(evm_loader_id, before=minimal_tx)
            logger.debug("{:>3} get_signatures_for_address {}".format(counter, len(result["result"])))
            counter += 1

            if len(result["result"]) == 0:
                logger.debug("len(result['result']) == 0")
                break

            for tx in result["result"]:
                solana_signature = tx["signature"]
                slot = tx["slot"]

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
        pool = ThreadPool(2)
        results = pool.map(self.get_tx_receipts, poll_txs)

        for transaction in results:
            (solana_signature, trx) = transaction
            self.transaction_receipts[solana_signature] = json.dumps(trx)

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


    def get_tx_receipts(self, solana_signature):
        trx = None
        retry = True

        while retry:
            try:
                trx = self.client.get_confirmed_transaction(solana_signature)['result']
                retry = False
            except Exception as err:
                logger.debug(err)
                import time
                time.sleep(1)

        return (solana_signature, trx)


    def process_receipts(self):
        counter = 0
        holder_table = {}
        continue_table = {}

        for signature in self.transaction_order:
            counter += 1

            if signature in self.sol_eth_trx:
                continue

            if signature in self.transaction_receipts:
                trx = json.loads(self.transaction_receipts[signature])
                if trx is None:
                    logger.debug("trx is None")
                    time.sleep(1)
                    continue
                if 'slot' not in trx:
                    logger.debug("\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))
                    exit()
                slot = trx['slot']
                if trx['transaction']['message']['instructions'] is not None:
                    for instruction in trx['transaction']['message']['instructions']:
                        instruction_data = base58.b58decode(instruction['data'])

                        if instruction_data[0] == 0x00: # Write
                            # logger.debug("{:>10} {:>6} Write 0x{}".format(slot, counter, instruction_data[-20:].hex()))
                            write_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if check_error(trx):
                                continue

                            if write_account in holder_table:
                                storage_account = holder_table[write_account].storage_account
                                if storage_account in continue_table:
                                    continue_table[storage_account].signatures.append(signature)

                                offset = int.from_bytes(instruction_data[4:8], "little")
                                length = int.from_bytes(instruction_data[8:16], "little")
                                data = instruction_data[16:]

                                logger.debug("WRITE offset {} length {}".format(offset, length))

                                if holder_table[write_account].max_written < (offset + length):
                                    holder_table[write_account].max_written = offset + length

                                for index in range(length):
                                    holder_table[write_account].data[1+offset+index] = data[index]
                                    holder_table[write_account].count_written += 1

                                if holder_table[write_account].max_written == holder_table[write_account].count_written:
                                    logger.debug("WRITE {} {}".format(holder_table[write_account].max_written, holder_table[write_account].count_written))
                                    signature = holder_table[write_account].data[1:66]
                                    length = int.from_bytes(holder_table[write_account].data[66:74], "little")
                                    unsigned_msg = holder_table[write_account].data[74:74+length]

                                    try:
                                        (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, signature)
                                        if len(eth_trx) / 2 > holder_table[write_account].max_written:
                                            logger.debug("WRITE got {} exp {}".format(len(eth_trx), holder_table[write_account].max_written))
                                            continue

                                        if storage_account in continue_table:
                                            # (logs, status, gas_used, return_value, slot) = continue_table[storage_account]
                                            continue_result = continue_table[storage_account]
                                            for rec in continue_result.logs:
                                                rec['transactionHash'] = eth_signature

                                            logger.debug(eth_signature + " " + continue_result.status)

                                            # transactions_glob[eth_signature] = TransactionInfo(eth_trx, slot, logs, status, gas_used, return_value)
                                            self.ethereum_trx[eth_signature] = json.dumps( {
                                                'eth_trx': eth_trx,
                                                'slot': continue_result.slot,
                                                'logs': continue_result.logs,
                                                'status': continue_result.status,
                                                'gas_used': continue_result.gas_used,
                                                'return_value': continue_result.return_value,
                                                'from_address': from_address,
                                            } )
                                            self.eth_sol_trx[eth_signature] = json.dumps(continue_result.signatures)
                                            for sig in continue_result.signatures:
                                                self.sol_eth_trx[sig] = eth_signature

                                            del continue_table[storage_account]
                                        else:
                                            logger.error("Storage not found")
                                            logger.error(eth_signature, "unknown")
                                            # raise

                                        del holder_table[write_account]
                                    except rlp.exceptions.DecodingError:
                                        logger.debug("DecodingError")
                                        pass
                                    except Exception as err:
                                        logger.debug("could not parse trx {}".format(err))
                                        pass

                        if instruction_data[0] == 0x01: # Finalize
                            # logger.debug("{:>10} {:>6} Finalize 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue
                            pass

                        if instruction_data[0] == 0x02: # CreateAccount
                            # logger.debug("{:>10} {:>6} CreateAccount 0x{}".format(slot, counter, instruction_data[-21:-1].hex()))

                            if check_error(trx):
                                continue
                            pass

                        if instruction_data[0] == 0x03: # Call
                            # logger.debug("{:>10} {:>6} Call 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue
                            pass

                        if instruction_data[0] == 0x04: # CreateAccountWithSeed
                            # logger.debug("{:>10} {:>6} CreateAccountWithSeed 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue
                            pass

                        if instruction_data[0] == 0x05: # CallFromRawTrx
                            # logger.debug("{:>10} {:>6} CallFromRawTrx 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue

                            # collateral_pool_buf = instruction_data[1:5]

                            # from_addr = instruction_data[5:25]

                            sign = instruction_data[25:90]
                            unsigned_msg = instruction_data[90:]

                            (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                            got_result = get_trx_results(trx)
                            if got_result is not None:
                                (logs, status, gas_used, return_value, slot) = got_result
                                for rec in logs:
                                    rec['transactionHash'] = eth_signature

                                logger.debug(eth_signature + " " + status)

                                # transactions_glob[eth_signature] = TransactionInfo(eth_trx, slot, logs, status, gas_used, return_value)
                                self.ethereum_trx[eth_signature] = json.dumps( {
                                    'eth_trx': eth_trx,
                                    'slot': slot,
                                    'logs': logs,
                                    'status': status,
                                    'gas_used': gas_used,
                                    'return_value': return_value,
                                    'from_address': from_address,
                                } )
                                self.eth_sol_trx[eth_signature] = json.dumps([signature])
                                self.sol_eth_trx[signature] = eth_signature
                            else:
                                logger.debug("RESULT NOT FOUND IN 05\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))
                                time.sleep(60)

                        if instruction_data[0] == 0x09: # PartialCallFromRawEthereumTX
                            # logger.debug("{:>10} {:>6} PartialCallFromRawEthereumTX 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if storage_account in continue_table:
                                # collateral_pool_buf = instruction_data[1:5]
                                # step_count = instruction_data[5:13]
                                # from_addr = instruction_data[13:33]

                                sign = instruction_data[33:98]
                                unsigned_msg = instruction_data[98:]

                                (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                                continue_result = continue_table[storage_account]
                                for rec in continue_result.logs:
                                    rec['transactionHash'] = eth_signature

                                logger.debug(eth_signature + " " + continue_result.status)

                                # transactions_glob[eth_signature] = TransactionInfo(eth_trx, slot, logs, status, gas_used, return_value)
                                self.ethereum_trx[eth_signature] = json.dumps( {
                                    'eth_trx': eth_trx,
                                    'slot': continue_result.slot,
                                    'logs': continue_result.logs,
                                    'status': continue_result.status,
                                    'gas_used': continue_result.gas_used,
                                    'return_value': continue_result.return_value,
                                    'from_address': from_address,
                                } )
                                self.eth_sol_trx[eth_signature] = json.dumps(continue_result.signatures)
                                for sig in continue_result.signatures:
                                    self.sol_eth_trx[sig] = eth_signature

                                del continue_table[storage_account]
                            else:
                                logger.debug("Storage not found")
                                pass

                        if instruction_data[0] == 0x0a: # Continue
                            # logger.debug("{:>10} {:>6} Continue 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)
                            else:
                                got_result = get_trx_results(trx)
                                if got_result is not None:
                                    (logs, status, gas_used, return_value, slot) = got_result
                                    continue_table[storage_account] =  ContinueStruct(signature, logs, status, gas_used, return_value, slot)
                                else:
                                    logger.error("Result not found")


                        if instruction_data[0] == 0x0b: # ExecuteTrxFromAccountDataIterative
                            # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterative 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue

                            holder_account =  trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)

                                if holder_account in holder_table:
                                    # logger.debug("holder_account found")
                                    # logger.debug("Strange behavior. Pay attention.")
                                    holder_table[holder_account] = HolderStruct(storage_account)
                                else:
                                    holder_table[holder_account] = HolderStruct(storage_account)

                        if instruction_data[0] == 0x0c: # Cancel
                            # logger.debug("{:>10} {:>6} Cancel 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            continue_table[storage_account] = ContinueStruct(signature, None, None, None, None, None)

                        if instruction_data[0] > 0x0c:
                            # logger.debug("{:>10} {:>6} Unknown 0x{}".format(slot, counter, instruction_data.hex()))

                            if check_error(trx):
                                continue


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    indexer = Indexer()
    indexer.run()
