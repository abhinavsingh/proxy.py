import base58
import rlp
import json
import os
import time
import logging
from web3 import Web3
from web3.auto.gethdev import w3
from solana.rpc.api import Client
from multiprocessing.dummy import Pool as ThreadPool
from sqlite_key_value import KeyValueStore


solana_url = os.environ.get("SOLANA_URL", "https://api.devnet.solana.com")
evm_loader_id = os.environ.get("EVM_LOADER", "eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU")

logger = logging.getLogger(__name__)

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
            time.sleep(15)


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
                                storage_account = holder_table[write_account][0]
                                if storage_account in continue_table:
                                    continue_table[storage_account].signatures.append(signature)

                                offset = int.from_bytes(instruction_data[4:8], "little")
                                length = int.from_bytes(instruction_data[8:16], "little")
                                data = instruction_data[16:]

                                for index in range(length):
                                    holder_table[write_account][1][1+offset+index] = data[index]

                                signature = holder_table[write_account][1][1:66]
                                length = int.from_bytes(holder_table[write_account][1][66:74], "little")
                                unsigned_msg = holder_table[write_account][1][74:74+length]

                                try:
                                    (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, signature)

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
                                    holder_table[holder_account] = (storage_account, bytearray(128*1024))
                                else:
                                    holder_table[holder_account] = (storage_account, bytearray(128*1024))

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

def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        logger.debug("Got err trx")
        logger.debug("\n{}".format(json.dumps(trx['meta']['err'])))
        time.sleep(1)
        return True
    return False

def get_trx_results(trx):
    slot = trx['slot']
    block_number = hex(slot)
    block_hash = '0x%064x'%slot
    got_result = False
    logs = []
    status = "0x1"
    gas_used = 0
    return_value = bytes
    log_index = 0
    for inner in (trx['meta']['innerInstructions']):
        for event in inner['instructions']:
            log = base58.b58decode(event['data'])
            instruction = log[:1]
            if (int().from_bytes(instruction, "little") == 7):  # OnEvent evmInstruction code
                address = log[1:21]
                count_topics = int().from_bytes(log[21:29], 'little')
                topics = []
                pos = 29
                for _ in range(count_topics):
                    topic_bin = log[pos:pos + 32]
                    topics.append('0x'+topic_bin.hex())
                    pos += 32
                data = log[pos:]
                rec = { 'address': '0x'+address.hex(),
                        'topics': topics,
                        'data': '0x'+data.hex(),
                        'transactionLogIndex': hex(0),
                        'transactionIndex': hex(inner['index']),
                        'blockNumber': block_number,
                        # 'transactionHash': trxId, # set when transaction found
                        'logIndex': hex(log_index),
                        'blockHash': block_hash
                    }
                logs.append(rec)
                log_index +=1
            elif int().from_bytes(instruction, "little") == 6:  # OnReturn evmInstruction code
                got_result = True
                if log[1] < 0xd0:
                    status = "0x1"
                else:
                    status = "0x0"
                gas_used = int.from_bytes(log[2:10], 'little')
                return_value = log[10:].hex()

    if got_result:
        return (logs, status, gas_used, return_value, slot)
    else:
        return None


def get_trx_receipts(unsigned_msg, signature):
    eth_trx = rlp.decode(unsigned_msg)

    eth_trx[6] = int(signature[64]) + 35 + 2 * int.from_bytes(eth_trx[6], "little")
    eth_trx[7] = signature[:32]
    eth_trx[8] = signature[32:64]

    eth_trx_raw = rlp.encode(eth_trx)

    eth_signature = '0x' + bytes(Web3.keccak(eth_trx_raw)).hex()
    from_address = w3.eth.account.recover_transaction(eth_trx_raw.hex())

    return (eth_trx_raw.hex(), eth_signature, from_address)


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    indexer = Indexer()
    indexer.run()
