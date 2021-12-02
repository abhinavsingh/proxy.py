from proxy.indexer.indexer_base import logger, IndexerBase, PARALLEL_REQUESTS
import base58
import json
import logging
import os
import rlp
import time
import logging
from multiprocessing.dummy import Pool as ThreadPool


try:
    from utils import check_error, get_trx_results, get_trx_receipts, LogDB, Canceller
    from sql_dict import SQLDict
except ImportError:
    from .utils import check_error, get_trx_results, get_trx_receipts, LogDB, Canceller
    from .sql_dict import SQLDict

CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", "60"))
UPDATE_BLOCK_COUNT = PARALLEL_REQUESTS * 16

class HolderStruct:
    def __init__(self, storage_account):
        self.storage_account = storage_account
        self.data = bytearray(128*1024)
        self.count_written = 0
        self.max_written = 0


class ContinueStruct:
    def __init__(self, signature, results, accounts = None):
        self.signatures = [signature]
        self.results = results
        self.accounts = accounts


class TransactionStruct:
    def __init__(self, eth_trx, eth_signature, from_address, got_result, signatures, storage, blocked_accounts, slot):
        # logger.debug(eth_signature)
        self.eth_trx = eth_trx
        self.eth_signature = eth_signature
        self.from_address = from_address
        self.got_result = got_result
        self.signatures = signatures
        self.storage = storage
        self.blocked_accounts = blocked_accounts
        self.slot = slot


class Indexer(IndexerBase):
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 log_level = 'INFO'):
        IndexerBase.__init__(self, solana_url, evm_loader_id, log_level)

        self.canceller = Canceller()
        self.logs_db = LogDB()
        self.blocks_by_hash = SQLDict(tablename="solana_blocks_by_hash")
        self.ethereum_trx = SQLDict(tablename="ethereum_transactions")
        self.eth_sol_trx = SQLDict(tablename="ethereum_solana_transactions")
        self.sol_eth_trx = SQLDict(tablename="solana_ethereum_transactions")
        self.constants = SQLDict(tablename="constants")
        if 'last_block' not in self.constants:
            self.constants['last_block'] = 0
        self.blocked_storages = {}


    def process_functions(self):
        IndexerBase.process_functions(self)
        logger.debug("Process receipts")
        self.process_receipts()
        logger.debug("Start getting blocks")
        self.gather_blocks()
        logger.debug("Unlock accounts")
        self.canceller.unlock_accounts(self.blocked_storages)
        self.blocked_storages = {}


    def process_receipts(self):
        counter = 0
        holder_table = {}
        continue_table = {}
        trx_table = {}

        for signature in self.transaction_order:
            counter += 1

            if signature in self.sol_eth_trx:
                continue

            if signature in self.transaction_receipts:
                trx = self.transaction_receipts[signature]
                if trx is None:
                    logger.error("trx is None")
                    del self.transaction_receipts[signature]
                    continue
                if 'slot' not in trx:
                    logger.debug("\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))
                    exit()
                slot = trx['slot']
                if trx['transaction']['message']['instructions'] is not None:
                    for instruction in trx['transaction']['message']['instructions']:

                        if trx["transaction"]["message"]["accountKeys"][instruction["programIdIndex"]] != self.evm_loader_id:
                            continue

                        if check_error(trx):
                            continue

                        instruction_data = base58.b58decode(instruction['data'])

                        if instruction_data[0] == 0x00 or instruction_data[0] == 0x12: # Write or WriteWithHolder
                            # if instruction_data[0] == 0x00:
                            #     logger.debug("{:>10} {:>6} Write 0x{}".format(slot, counter, instruction_data[-20:].hex()))
                            # if instruction_data[0] == 0x12:
                            #     logger.debug("{:>10} {:>6} WriteWithHolder 0x{}".format(slot, counter, instruction_data[-20:].hex()))

                            write_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if write_account in holder_table:
                                storage_account = holder_table[write_account].storage_account
                                if storage_account in continue_table:
                                    continue_table[storage_account].signatures.append(signature)

                                if instruction_data[0] == 0x00:
                                    offset = int.from_bytes(instruction_data[4:8], "little")
                                    length = int.from_bytes(instruction_data[8:16], "little")
                                    data = instruction_data[16:]
                                if instruction_data[0] == 0x12:
                                    offset = int.from_bytes(instruction_data[9:13], "little")
                                    length = int.from_bytes(instruction_data[13:21], "little")
                                    data = instruction_data[21:]

                                # logger.debug("WRITE offset {} length {}".format(offset, length))

                                if holder_table[write_account].max_written < (offset + length):
                                    holder_table[write_account].max_written = offset + length

                                for index in range(length):
                                    holder_table[write_account].data[1+offset+index] = data[index]
                                    holder_table[write_account].count_written += 1

                                if holder_table[write_account].max_written == holder_table[write_account].count_written:
                                    # logger.debug("WRITE {} {}".format(holder_table[write_account].max_written, holder_table[write_account].count_written))
                                    signature = holder_table[write_account].data[1:66]
                                    length = int.from_bytes(holder_table[write_account].data[66:74], "little")
                                    unsigned_msg = holder_table[write_account].data[74:74+length]

                                    try:
                                        (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, signature)
                                        if len(eth_trx) / 2 > holder_table[write_account].max_written:
                                            logger.debug("WRITE got {} exp {}".format(len(eth_trx), holder_table[write_account].max_written))
                                            continue

                                        if storage_account in continue_table:
                                            continue_result = continue_table[storage_account]

                                            # logger.debug(eth_signature)
                                            trx_table[eth_signature] = TransactionStruct(
                                                    eth_trx,
                                                    eth_signature,
                                                    from_address,
                                                    continue_result.results,
                                                    continue_result.signatures,
                                                    storage_account,
                                                    continue_result.accounts,
                                                    slot
                                                )

                                            del continue_table[storage_account]
                                        else:
                                            logger.error("Storage not found")
                                            logger.error(eth_signature, "unknown")
                                            # raise

                                        del holder_table[write_account]
                                    except rlp.exceptions.RLPException:
                                        # logger.debug("rlp.exceptions.RLPException")
                                        pass
                                    except Exception as err:
                                        if str(err).startswith("nonhashable type"):
                                            # logger.debug("nonhashable type")
                                            pass
                                        elif str(err).startswith("unsupported operand type"):
                                            # logger.debug("unsupported operand type")
                                            pass
                                        else:
                                            logger.debug("could not parse trx {}".format(err))
                                            raise

                        elif instruction_data[0] == 0x01: # Finalize
                            # logger.debug("{:>10} {:>6} Finalize 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

                        elif instruction_data[0] == 0x02: # CreateAccount
                            # logger.debug("{:>10} {:>6} CreateAccount 0x{}".format(slot, counter, instruction_data[-21:-1].hex()))

                            pass

                        elif instruction_data[0] == 0x03: # Call
                            # logger.debug("{:>10} {:>6} Call 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

                        elif instruction_data[0] == 0x04: # CreateAccountWithSeed
                            # logger.debug("{:>10} {:>6} CreateAccountWithSeed 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

                        elif instruction_data[0] == 0x05: # CallFromRawTrx
                            # logger.debug("{:>10} {:>6} CallFromRawTrx 0x{}".format(slot, counter, instruction_data.hex()))

                            # collateral_pool_buf = instruction_data[1:5]
                            # from_addr = instruction_data[5:25]
                            sign = instruction_data[25:90]
                            unsigned_msg = instruction_data[90:]

                            (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                            got_result = get_trx_results(trx)
                            if got_result is not None:
                                # self.submit_transaction(eth_trx, eth_signature, from_address, got_result, [signature])
                                trx_table[eth_signature] = TransactionStruct(
                                        eth_trx,
                                        eth_signature,
                                        from_address,
                                        got_result,
                                        [signature],
                                        None,
                                        None,
                                        slot
                                    )
                            else:
                                logger.error("RESULT NOT FOUND IN 05\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))

                        elif instruction_data[0] == 0x09 or instruction_data[0] == 0x13: # PartialCallFromRawEthereumTX PartialCallFromRawEthereumTXv02
                            # if instruction_data[0] == 0x09:
                            #     logger.debug("{:>10} {:>6} PartialCallFromRawEthereumTX 0x{}".format(slot, counter, instruction_data.hex()))
                            # if instruction_data[0] == 0x13:
                            #     logger.debug("{:>10} {:>6} PartialCallFromRawEthereumTXv02 0x{}".format(slot, counter, instruction_data.hex()))


                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][7:]]

                            # collateral_pool_buf = instruction_data[1:5]
                            # step_count = instruction_data[5:13]
                            # from_addr = instruction_data[13:33]

                            sign = instruction_data[33:98]
                            unsigned_msg = instruction_data[98:]

                            (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                            trx_table[eth_signature] = TransactionStruct(
                                    eth_trx,
                                    eth_signature,
                                    from_address,
                                    None,
                                    [signature],
                                    storage_account,
                                    blocked_accounts,
                                    slot
                                )

                            if storage_account in continue_table:
                                continue_result = continue_table[storage_account]
                                if continue_result.accounts != blocked_accounts:
                                    logger.error("Strange behavior. Pay attention. BLOCKED ACCOUNTS NOT EQUAL")
                                trx_table[eth_signature].got_result = continue_result.results
                                trx_table[eth_signature].signatures += continue_result.signatures

                                del continue_table[storage_account]

                        elif instruction_data[0] == 0x0a or instruction_data[0] == 0x14: # Continue or ContinueV02

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            if instruction_data[0] == 0x0a:
                                # logger.debug("{:>10} {:>6} Continue 0x{}".format(slot, counter, instruction_data.hex()))
                                blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][5:]]
                            if instruction_data[0] == 0x14:
                                # logger.debug("{:>10} {:>6} ContinueV02 0x{}".format(slot, counter, instruction_data.hex()))
                                blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][6:]]
                            got_result = get_trx_results(trx)

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)

                                if got_result is not None:
                                    if continue_table[storage_account].results is not None:
                                        logger.error("Strange behavior. Pay attention. RESULT ALREADY EXISTS IN CONTINUE TABLE")
                                    if continue_table[storage_account].accounts != blocked_accounts:
                                        logger.error("Strange behavior. Pay attention. BLOCKED ACCOUNTS NOT EQUAL")

                                    continue_table[storage_account].results = got_result
                            else:
                                continue_table[storage_account] = ContinueStruct(signature, got_result, blocked_accounts)

                        elif instruction_data[0] == 0x0b or instruction_data[0] == 0x16: # ExecuteTrxFromAccountDataIterative ExecuteTrxFromAccountDataIterativeV02
                            if instruction_data[0] == 0x0b:
                                # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterative 0x{}".format(slot, counter, instruction_data.hex()))
                                blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][5:]]
                            if instruction_data[0] == 0x16:
                                # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterativeV02 0x{}".format(slot, counter, instruction_data.hex()))
                                blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][7:]]

                            holder_account =  trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)

                                if holder_account in holder_table:
                                    if holder_table[holder_account].storage_account != storage_account:
                                        logger.error("Strange behavior. Pay attention. STORAGE_ACCOUNT != STORAGE_ACCOUNT")
                                        holder_table[holder_account] = HolderStruct(storage_account)
                                else:
                                    holder_table[holder_account] = HolderStruct(storage_account)
                            else:
                                continue_table[storage_account] =  ContinueStruct(signature, None, blocked_accounts)
                                holder_table[holder_account] = HolderStruct(storage_account)


                        elif instruction_data[0] == 0x0c or instruction_data[0] == 0x15: # Cancel
                            # logger.debug("{:>10} {:>6} Cancel 0x{}".format(slot, counter, instruction_data.hex()))

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][6:]]

                            continue_table[storage_account] = ContinueStruct(signature, ([], "0x0", 0, [], trx['slot']), blocked_accounts)

                        elif instruction_data[0] == 0x0d:
                            # logger.debug("{:>10} {:>6} PartialCallOrContinueFromRawEthereumTX 0x{}".format(slot, counter, instruction_data.hex()))

                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][7:]]
                            got_result = get_trx_results(trx)

                            # collateral_pool_buf = instruction_data[1:5]
                            # step_count = instruction_data[5:13]
                            # from_addr = instruction_data[13:33]

                            sign = instruction_data[33:98]
                            unsigned_msg = instruction_data[98:]

                            (eth_trx, eth_signature, from_address) = get_trx_receipts(unsigned_msg, sign)

                            if eth_signature in trx_table:
                                trx_table[eth_signature].signatures.append(signature)
                            else:
                                trx_table[eth_signature] = TransactionStruct(
                                        eth_trx,
                                        eth_signature,
                                        from_address,
                                        got_result,
                                        [signature],
                                        storage_account,
                                        blocked_accounts,
                                        slot
                                    )

                            if storage_account in continue_table:
                                continue_result = continue_table[storage_account]
                                trx_table[eth_signature].signatures += continue_result.signatures
                                if continue_result.results is not None:
                                    trx_table[eth_signature].got_result = continue_result.results

                                del continue_table[storage_account]

                        elif instruction_data[0] == 0x0e:
                            # logger.debug("{:>10} {:>6} ExecuteTrxFromAccountDataIterativeOrContinue 0x{}".format(slot, counter, instruction_data.hex()))

                            holder_account =  trx['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            storage_account = trx['transaction']['message']['accountKeys'][instruction['accounts'][1]]
                            blocked_accounts = [trx['transaction']['message']['accountKeys'][acc_idx] for acc_idx in instruction['accounts'][7:]]
                            got_result = get_trx_results(trx)

                            if storage_account in continue_table:
                                continue_table[storage_account].signatures.append(signature)

                                if holder_account in holder_table:
                                    if holder_table[holder_account].storage_account != storage_account:
                                        logger.error("Strange behavior. Pay attention. STORAGE_ACCOUNT != STORAGE_ACCOUNT")
                                        holder_table[holder_account] = HolderStruct(storage_account)
                                else:
                                    logger.error("Strange behavior. Pay attention. HOLDER ACCOUNT NOT FOUND")
                                    holder_table[holder_account] = HolderStruct(storage_account)

                                if got_result is not None:
                                    if continue_table[storage_account].results:
                                        logger.error("Strange behavior. Pay attention. RESULT ALREADY EXISTS IN CONTINUE TABLE")
                                    if continue_table[storage_account].accounts != blocked_accounts:
                                        logger.error("Strange behavior. Pay attention. BLOCKED ACCOUNTS NOT EQUAL")

                                    continue_table[storage_account].results = got_result
                            else:
                                continue_table[storage_account] =  ContinueStruct(signature, got_result, blocked_accounts)
                                holder_table[holder_account] = HolderStruct(storage_account)

                        if instruction_data[0] > 0x16:
                            logger.debug("{:>10} {:>6} Unknown 0x{}".format(slot, counter, instruction_data.hex()))

                            pass

        for eth_signature, trx_struct in trx_table.items():
            if trx_struct.got_result is not None:
                self.submit_transaction(trx_struct)
            elif trx_struct.storage is not None:
                if not self.submit_transaction_part(trx_struct):
                    if abs(trx_struct.slot - self.current_slot) > CANCEL_TIMEOUT:
                        logger.debug("Probably blocked")
                        logger.debug(trx_struct.eth_signature)
                        logger.debug(trx_struct.signatures)
                        self.blocked_storages[trx_struct.storage] = (trx_struct.eth_trx, trx_struct.blocked_accounts)
            else:
                logger.error(trx_struct)


    def submit_transaction(self, trx_struct):
        (logs, status, gas_used, return_value, slot) = trx_struct.got_result
        (_slot, block_hash) = self.get_block(slot)
        if logs:
            for rec in logs:
                rec['transactionHash'] = trx_struct.eth_signature
                rec['blockHash'] = block_hash
            self.logs_db.push_logs(logs)
        self.ethereum_trx[trx_struct.eth_signature] = {
            'eth_trx': trx_struct.eth_trx,
            'slot': slot,
            'logs': logs,
            'status': status,
            'gas_used': gas_used,
            'return_value': return_value,
            'from_address': trx_struct.from_address,
        }
        self.eth_sol_trx[trx_struct.eth_signature] = trx_struct.signatures
        for idx, sig in enumerate(trx_struct.signatures):
            self.sol_eth_trx[sig] = {
                'idx': idx,
                'eth': trx_struct.eth_signature,
            }
        self.blocks_by_hash[block_hash] = slot

        logger.debug(trx_struct.eth_signature + " " + status)


    def submit_transaction_part(self, trx_struct):
        ''' Check if transaction was allready submitted by proxy. '''
        eth_signature = trx_struct.eth_signature
        ethereum_trx = self.ethereum_trx.get(eth_signature, None)
        if ethereum_trx is not None:
            signatures = self.eth_sol_trx.get(eth_signature, [])
            signatures = signatures + trx_struct.signatures
            self.eth_sol_trx[eth_signature] = signatures
            for idx, sig in enumerate(signatures):
                self.sol_eth_trx[sig] = {
                    'idx': idx,
                    'eth': eth_signature,
                }
            return True
        return False


    def gather_blocks(self):
        max_slot = self.client.get_slot(commitment="recent")["result"]

        last_block = self.constants['last_block']
        if last_block + UPDATE_BLOCK_COUNT < max_slot:
            max_slot = last_block + UPDATE_BLOCK_COUNT
        slots = self.client._provider.make_request("getBlocks", last_block, max_slot, {"commitment": "confirmed"})["result"]

        pool = ThreadPool(PARALLEL_REQUESTS)
        results = pool.map(self.get_block, slots)

        for block_result in results:
            (slot, block_hash) = block_result
            self.blocks_by_hash[block_hash] = slot

        self.constants['last_block'] = max_slot


    def get_block(self, slot):
        retry = True

        while retry:
            try:
                block = self.client._provider.make_request("getBlock", slot, {"commitment":"confirmed", "transactionDetails":"none", "rewards":False})['result']
                block_hash = '0x' + base58.b58decode(block['blockhash']).hex()
                retry = False
            except Exception as err:
                logger.debug(err)
                time.sleep(1)

        return (slot, block_hash)


def run_indexer(solana_url,
                evm_loader_id,
                log_level = 'DEBUG'):
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id},
        log_level: {log_level}""")

    indexer = Indexer(solana_url,
                      evm_loader_id,
                      log_level)
    indexer.run()


if __name__ == "__main__":
    solana_url = os.environ.get('SOLANA_URL', 'http://localhost:8899')
    evm_loader_id = os.environ.get('EVM_LOADER_ID', '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io')
    log_level = os.environ.get('LOG_LEVEL', 'INFO')

    run_indexer(solana_url,
                evm_loader_id,
                log_level)
