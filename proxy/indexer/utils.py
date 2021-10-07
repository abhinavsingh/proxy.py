import base58
import rlp
import json
import time
import sqlite3
import logging
from web3 import Web3
from web3.auto.gethdev import w3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        # logger.debug("Got err trx")
        # logger.debug("\n{}".format(json.dumps(trx['meta']['err'])))
        return True
    return False

def get_trx_results(trx):
    slot = trx['slot']
    block_number = hex(slot)
    # block_hash = '0x%064x'%slot
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
                rec = {
                    'address': '0x'+address.hex(),
                    'topics': topics,
                    'data': '0x'+data.hex(),
                    'transactionLogIndex': hex(0),
                    'transactionIndex': hex(inner['index']),
                    'blockNumber': block_number,
                    # 'transactionHash': trxId, # set when transaction found
                    'logIndex': hex(log_index),
                    # 'blockHash': block_hash # set when transaction found
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

class LogDB:
    def __init__(self, filename="local.db"):
        self.conn = sqlite3.connect(filename, check_same_thread=False) # multithread mode
        # self.conn.isolation_level = None # autocommit mode
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS
        logs (
            address TEXT,
            blockHash TEXT,
            blockNumber INT,
            topic TEXT,

            transactionHash TEXT,
            transactionLogIndex INT,

            json TEXT,
            UNIQUE(transactionLogIndex, transactionHash, topic) ON CONFLICT IGNORE
        );""")
        self.conn.commit()

    def push_logs(self, logs):
        rows = []
        for log in logs:
            for topic in log['topics']:
                rows.append(
                    (
                        log['address'],
                        log['blockHash'],
                        int(log['blockNumber'], 16),
                        topic,
                        log['transactionHash'],
                        int(log['transactionLogIndex'], 16),
                        json.dumps(log)
                    )
                )
        if len(rows):
            logger.debug(rows)
            cur = self.conn.cursor()
            cur.executemany('INSERT INTO logs VALUES (?, ?, ?, ?,  ?, ?,  ?)', rows)
            self.conn.commit()
        else:
            logger.debug("NO LOGS")


    def get_logs(self, fromBlock = None, toBlock = None, address = None, topics = None, blockHash = None):
        queries = []
        params = []

        if fromBlock is not None:
            queries.append("blockNumber >= ?")
            params.append(fromBlock)

        if toBlock is not None:
            queries.append("blockNumber <= ?")
            params.append(toBlock)

        if blockHash is not None:
            blockHash = blockHash.lower()
            queries.append("blockHash = ?")
            params.append(blockHash)

        if topics is not None:
            topics = [item.lower() for item in topics]
            query_placeholder = ", ".join("?" * len(topics))
            topics_query = f"topic IN ({query_placeholder})"

            queries.append(topics_query)
            params += topics

        if address is not None:
            if isinstance(address, str):
                address = address.lower()
                queries.append("address = ?")
                params.append(address)
            elif isinstance(address, list):
                address = [item.lower() for item in address]
                query_placeholder = ", ".join("?" * len(address))
                address_query = f"address IN ({query_placeholder})"

                queries.append(address_query)
                params += address

        query_string = "SELECT * FROM logs WHERE "
        for idx, query in enumerate(queries):
            query_string += query
            if idx < len(queries) - 1:
                query_string += " AND "

        logger.debug(query_string)
        logger.debug(params)

        cur = self.conn.cursor()
        cur.execute(query_string, tuple(params))

        rows = cur.fetchall()

        logs = set()
        for row in rows:
            logs.add(row[-1])
        return_list = []
        for log in logs:
            return_list.append(json.loads(log))
        return return_list

    def __del__(self):
        self.conn.close()
