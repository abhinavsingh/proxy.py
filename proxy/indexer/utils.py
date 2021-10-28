import base58
import base64
import json
import logging
import os
import rlp
import sqlite3
import subprocess
from construct import Struct, Bytes, Int64ul
from eth_utils import big_endian_to_int
from ethereum.transactions import Transaction as EthTrx
from ethereum.utils import sha3
from solana.account import Account
from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.transaction import AccountMeta, Transaction, TransactionInstruction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from web3.auto.gethdev import w3


solana_url = os.environ.get("SOLANA_URL", "https://api.devnet.solana.com")
evm_loader_id = os.environ.get("EVM_LOADER", "eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU")
ETH_TOKEN_MINT_ID = os.environ.get("ETH_TOKEN_MINT", "89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g")
sysvarclock = "SysvarC1ock11111111111111111111111111111111"
sysinstruct = "Sysvar1nstructions1111111111111111111111111"
keccakprog = "KeccakSecp256k11111111111111111111111111111"
rentid = "SysvarRent111111111111111111111111111111111"
incinerator = "1nc1nerator11111111111111111111111111111111"
system = "11111111111111111111111111111111"


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        # logger.debug("Got err trx")
        # logger.debug("\n{}".format(json.dumps(trx['meta']['err'])))
        return True
    return False


def get_trx_results(trx):
    # init variables for instruction owner checks
    accounts = trx["transaction"]["message"]["accountKeys"]
    evm_loader_instructions = []
    for idx, instruction in enumerate(trx["transaction"]["message"]["instructions"]):
        if accounts[instruction["programIdIndex"]] == evm_loader_id:
            evm_loader_instructions.append(idx)

    slot = trx['slot']
    block_number = hex(slot)
    got_result = False
    logs = []
    status = "0x1"
    gas_used = 0
    return_value = bytes
    log_index = 0
    for inner in (trx['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == evm_loader_id:
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
    trx = rlp.decode(unsigned_msg, EthTrx)

    v = int(signature[64]) + 35 + 2 * trx[6]
    r = big_endian_to_int(signature[0:32])
    s = big_endian_to_int(signature[32:64])

    trx_raw = rlp.encode(EthTrx(trx[0], trx[1], trx[2], trx[3], trx[4], trx[5], v, r, s), EthTrx)
    eth_signature = '0x' + sha3(trx_raw).hex()
    from_address = w3.eth.account.recover_transaction(trx_raw).lower()

    return (trx_raw.hex(), eth_signature, from_address)

STORAGE_ACCOUNT_INFO_LAYOUT = Struct(
    # "tag" / Int8ul,
    "caller" / Bytes(20),
    "nonce" / Int64ul,
    "gas_limit" / Int64ul,
    "gas_price" / Int64ul,
    "slot" / Int64ul,
    "operator" / Bytes(32),
    "accounts_len" / Int64ul,
    "executor_data_size" / Int64ul,
    "evm_data_size" / Int64ul,
    "gas_used_and_paid" / Int64ul,
    "number_of_payments" / Int64ul,
)

def get_account_list(client, storage_account):
    opts = {
        "encoding": "base64",
        "commitment": "confirmed",
        "dataSlice": {
            "offset": 0,
            "length": 2048,
        }
    }
    result = client._provider.make_request("getAccountInfo", str(storage_account), opts)
    # logger.debug("\n{}".format(json.dumps(result, indent=4, sort_keys=True)))

    info = result['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(storage_account))

    data = base64.b64decode(info['data'][0])

    tag = data[0]
    if tag == 0:
        logger.debug("Empty")
        return None
    elif tag == 3:
        logger.debug("Not empty storage")

        acc_list = []
        storage = STORAGE_ACCOUNT_INFO_LAYOUT.parse(data[1:])
        offset = 1 + STORAGE_ACCOUNT_INFO_LAYOUT.sizeof()
        for _ in range(storage.accounts_len):
            some_pubkey = PublicKey(data[offset:offset + 32])
            acc_list.append(some_pubkey)
            offset += 32

        return acc_list
    else:
        logger.debug("Not empty other")
        return None


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
            # logger.debug(rows)
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


class Canceller:
    def __init__(self):
        # Initialize user account
        res = self.call('config', 'get')
        substr = "Keypair Path: "
        path = ""
        for line in res.splitlines():
            if line.startswith(substr):
                path = line[len(substr):].strip()
        if path == "":
            raise Exception("cannot get keypair path")

        with open(path.strip(), mode='r') as file:
            pk = (file.read())
            numbs = list(map(int, pk.strip("[] \n").split(',')))
            numbs = numbs[0:32]
            values = bytes(numbs)
            self.signer = Account(values)

        self.client = Client(solana_url)

        self.operator = self.signer.public_key()
        self.operator_token = get_associated_token_address(PublicKey(self.operator), PublicKey(ETH_TOKEN_MINT_ID))


    def call(self, *args):
        try:
            cmd = ["solana",
                   "--url", solana_url,
                   ] + list(args)
            logger.debug(cmd)
            return subprocess.check_output(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            logger.debug("ERR: solana error {}".format(err))
            raise


    def unlock_accounts(self, blocked_storages):
        readonly_accs = [
            PublicKey(evm_loader_id),
            PublicKey(ETH_TOKEN_MINT_ID),
            PublicKey(TOKEN_PROGRAM_ID),
            PublicKey(sysvarclock),
            PublicKey(sysinstruct),
            PublicKey(keccakprog),
            PublicKey(rentid),
            PublicKey(incinerator),
            PublicKey(system),
        ]
        for storage in blocked_storages:
            acc_list = get_account_list(self.client, storage)
            if acc_list is not None:
                keys = [
                        AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                        AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=acc_list[4], is_signer=False, is_writable=True),
                        AccountMeta(pubkey=incinerator, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=system, is_signer=False, is_writable=False)
                    ]
                for acc in acc_list:
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=(False if acc in readonly_accs else True)))

                trx = Transaction()
                trx.add(TransactionInstruction(
                    program_id=evm_loader_id,
                    data=bytearray.fromhex("0C"),
                    keys=keys
                ))

                logger.debug("Send Cancel")
                try:
                    self.client.send_transaction(trx, self.signer, opts=TxOpts(preflight_commitment=Confirmed))
                except Exception as err:
                    logger.debug(err)
                else:
                    logger.debug("Canceled")
                    logger.debug(acc_list)
