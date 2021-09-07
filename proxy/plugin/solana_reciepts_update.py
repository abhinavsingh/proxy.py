import time
import os
import logging
from ..core.acceptor.pool import transactions_glob
import base58
from solana.rpc.api import Client
import base58
import rlp
import json
from web3 import Web3
from web3.auto.gethdev import w3
from solana.rpc.api import Client


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
evm_loader_id = os.environ.get("EVM_LOADER")


class TransactionInfo:
    def __init__(self, eth_trx, slot, logs, status, gas_used, return_value):
        self.eth_trx = eth_trx
        self.slot = slot
        self.logs = logs
        self.status = status
        self.gas_used = gas_used
        self.return_value = return_value

class Indexer:
    def run(self):
        self.client = Client(solana_url)
        self.last_slot = 0
        self.last_trx = None
        self.continue_table = {}
        self.holder_table = {}

        while (True):
            try:
                logger.debug("Start indexing")
                # do indexation
                self.poll()
                pass
            except Exception as err:
                logger.debug("Got exception while indexing. Type(err):%s, Exception:%s", type(err), err)
            time.sleep(60)

    def poll(self):
        minimal_tx = None
        minimal_slot = self.client.get_slot()["result"]
        while (True):
            result = self.client.get_signatures_for_address(evm_loader_id, before=minimal_tx)
            if len(result["result"]) == 0:
                break
            for tx in result["result"]:
                if tx["slot"] < minimal_slot:
                    minimal_slot = tx["slot"]
                    minimal_tx = tx["signature"]

                trx = self.client.get_confirmed_transaction(tx["signature"])

                if trx['result']['transaction']['message']['instructions'] is not None:
                    for instruction in trx['result']['transaction']['message']['instructions']:
                        instruction_data = base58.b58decode(instruction['data'])

                        if instruction_data[0] == 0x00: # Write
                            offset = int.from_bytes(instruction_data[4:8], "little")
                            length = int.from_bytes(instruction_data[8:16], "little")
                            data = instruction_data[16:]

                            write_account = trx['result']['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if write_account in self.holder_table:
                                for index in range(length):
                                    self.holder_table[write_account][1][1+offset+index] = data[index]

                                signature = self.holder_table[write_account][1][1:66]
                                length = int.from_bytes(self.holder_table[write_account][1][66:74], "little")
                                unsigned_msg = self.holder_table[write_account][1][74:74+length]

                                try:
                                    eth_trx = rlp.decode(unsigned_msg)

                                    eth_trx[6] = int(signature[64]) + 35 + 2 * int.from_bytes(eth_trx[6], "little")
                                    eth_trx[7] = signature[:32]
                                    eth_trx[8] = signature[32:64]

                                    # print(rlp.encode(eth_trx).hex())
                                    eth_signature = '0x' + bytes(Web3.keccak(rlp.encode(eth_trx))).hex()

                                    from_address = w3.eth.account.recover_transaction(rlp.encode(eth_trx).hex())

                                    storage_account = self.holder_table[write_account][0]

                                    if storage_account in self.continue_table:
                                        (logs, status, gas_used, return_value, slot) = self.continue_table[storage_account]
                                        for rec in logs:
                                            rec['transactionHash'] = eth_signature
                                        transactions_glob[eth_signature] = TransactionInfo(eth_trx, slot, logs, status, gas_used, return_value)

                                        del self.continue_table[storage_account]
                                    else:
                                        print("Storage not found")
                                        print(eth_signature, "unknown")
                                        # raise

                                    del self.holder_table[write_account]
                                except Exception as err:
                                    print("could not parse trx", err)
                                    pass

                        if instruction_data[0] == 0x01: # Finalize
                            # print("{:>6} Finalize 0x{}".format(counter, instruction_data.hex()))
                            pass

                        if instruction_data[0] == 0x02: # CreateAccount
                            # print("{:>6} CreateAccount 0x{}".format(counter, instruction_data[-21:-1].hex()))
                            pass

                        if instruction_data[0] == 0x03: # Call
                            # print("{:>6} Call 0x{}".format(counter, instruction_data.hex()))
                            pass

                        if instruction_data[0] == 0x04: # CreateAccountWithSeed
                            # print("{:>6} CreateAccountWithSeed 0x{}".format(counter, instruction_data.hex()))
                            pass

                        if instruction_data[0] == 0x05: # CallFromRawTrx
                            collateral_pool_buf = instruction_data[1:5]
                            from_addr = instruction_data[5:25]
                            sign = instruction_data[25:90]
                            unsigned_msg = instruction_data[90:]

                            eth_trx = rlp.decode(unsigned_msg)
                            eth_trx[6] = int(sign[64]) + 35 + 2 * int.from_bytes(eth_trx[6], "little")
                            eth_trx[7] = sign[:32]
                            eth_trx[8] = sign[32:64]

                            # print(rlp.encode(eth_trx).hex())
                            eth_signature = '0x' + bytes(Web3.keccak(rlp.encode(eth_trx))).hex()

                            from_address = w3.eth.account.recover_transaction(rlp.encode(eth_trx).hex())

                            (logs, status, gas_used, return_value, slot) = get_trx_results(trx)
                            transactions_glob[eth_signature] = TransactionInfo(eth_trx, slot, logs, status, gas_used, return_value)

                        if instruction_data[0] == 0x09: # PartialCallFromRawEthereumTX
                            collateral_pool_buf = instruction_data[1:5]
                            step_count = instruction_data[5:13]
                            from_addr = instruction_data[13:33]
                            sign = instruction_data[33:98]
                            unsigned_msg = instruction_data[98:]

                            eth_trx = rlp.decode(unsigned_msg)
                            eth_trx[6] = int(sign[64]) + 35 + 2 * int.from_bytes(eth_trx[6], "little")
                            eth_trx[7] = sign[:32]
                            eth_trx[8] = sign[32:64]

                            eth_signature = '0x' + bytes(Web3.keccak(rlp.encode(eth_trx))).hex()

                            from_address = w3.eth.account.recover_transaction(rlp.encode(eth_trx).hex())

                            storage_account = trx['result']['transaction']['message']['accountKeys'][instruction['accounts'][0]]

                            if storage_account in self.continue_table:
                                (logs, status, gas_used, return_value, slot) = self.continue_table[storage_account]
                                transactions_glob[eth_signature] = TransactionInfo(eth_trx, slot, logs, status, gas_used, return_value)

                                del self.continue_table[storage_account]
                            else:
                                print("Storage not found")
                                raise

                        if instruction_data[0] == 0x0a: # Continue
                            got_result = get_trx_results(trx)

                            if got_result is not None:
                                storage_account = trx['result']['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                                self.continue_table[storage_account] = got_result

                        if instruction_data[0] == 0x0b: # ExecuteTrxFromAccountDataIterative
                            holder_account =  trx['result']['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            storage_account = trx['result']['transaction']['message']['accountKeys'][instruction['accounts'][1]]

                            if holder_account in self.holder_table:
                                # print("holder_account found")
                                # print("Strange behavior. Pay attention.")
                                self.holder_table[holder_account] = (storage_account, bytearray(128*1024))
                            else:
                                self.holder_table[holder_account] = (storage_account, bytearray(128*1024))

                        if instruction_data[0] == 0x0c: # Cancel
                            storage_account = trx['result']['transaction']['message']['accountKeys'][instruction['accounts'][0]]
                            # continue_table[storage_account] = 0xff
                            self.continue_table[storage_account] = (None, None, None, None, None, None)


def get_trx_results(trx):
    slot = trx['result']['slot']
    block_number = hex(slot)
    block_hash = '0x%064x'%slot
    got_result = False
    logs = []
    status = "0x1"
    gas_used = 0
    return_value = bytes
    log_index = 0
    for inner in (trx['result']['meta']['innerInstructions']):
        for event in inner['instructions']:
            log = base58.b58decode(event['data'])
            instruction_data = log[:1]
            if (int().from_bytes(instruction_data, "little") == 7):  # OnEvent evmInstruction code
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
            elif int().from_bytes(instruction_data, "little") == 6:  # OnReturn evmInstruction code
                got_result = True
                if log[1] < 0xd0:
                    status = "0x1"
                else:
                    status = "0x0"
                gas_used = int.from_bytes(log[2:10], 'little')
                return_value = log[10:]

    if got_result:
        return (logs, status, gas_used, return_value, slot)
    else:
        return None
