import base58
import base64
import json
import logging
import os
import psycopg2
import rlp
import subprocess

from eth_utils import big_endian_to_int
from ethereum.transactions import Transaction as EthTx
from ethereum.utils import sha3
from solana.account import Account
from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_CLOCK_PUBKEY, SYSVAR_RENT_PUBKEY
from solana.transaction import AccountMeta, Transaction, TransactionInstruction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from web3.auto.gethdev import w3

from ..common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT
from ..environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        # logger.debug("Got err trx")
        # logger.debug("\n{}".format(json.dumps(trx['meta']['err'])))
        return True
    return False


def str_fmt_object(obj):
    name = f'{type(obj)}'
    name = name[name.rfind('.') + 1:-2]
    lookup = lambda o: o.__dict__ if hasattr(o, '__dict__') else None
    members = {json.dumps(obj, default=lookup, sort_keys=True)}
    return f'{name}: {members}'


class NeonIxSignInfo:
    def __init__(self, sign: bytes, slot: int, idx: int):
        self.sign = sign  # Solana transaction signature
        self.slot = slot  # Solana block slot
        self.idx  = idx   # Instruction index

    def __str__(self):
        return f'{self.slot} {self.sign} {self.idx}'

    def __hash__(self):
        return hash((self.sign, self.slot, self.idx))

    def __eq__(self, other):
        return (self.sign, self.slot, self.idx) == (other.sign, other.slot, other.idx)

    def copy(self):
        return NeonIxSignInfo(sign=self.sign, slot=self.slot, idx=self.idx)


class NeonTxResultInfo:
    def __init__(self, tx=None):
        if not isinstance(tx, dict):
            self._set_defaults()
        else:
            self.decode(tx)

    def __str__(self):
        return str_fmt_object(self)

    def _set_defaults(self):
        self.logs = []
        self.status = "0x0"
        self.gas_used = 0
        self.return_value = bytes()
        self.slot = -1
        self.error = None

    def _decode_event(self, log, tx_idx):
        log_idx = len(self.logs)
        address = log[1:21]
        count_topics = int().from_bytes(log[21:29], 'little')
        topics = []
        pos = 29
        for _ in range(count_topics):
            topic_bin = log[pos:pos + 32]
            topics.append('0x' + topic_bin.hex())
            pos += 32
        data = log[pos:]
        rec = {
            'address': '0x' + address.hex(),
            'topics': topics,
            'data': '0x' + data.hex(),
            'transactionLogIndex': hex(0),
            'transactionIndex': hex(tx_idx),
            # 'blockNumber': block_number, # set when transaction found
            # 'transactionHash': trxId, # set when transaction found
            'logIndex': hex(log_idx),
            # 'blockHash': block_hash # set when transaction found
        }
        self.logs.append(rec)

    def _decode_return(self, log, slot):
        self.status = '0x1' if log[1] < 0xd0 else '0x0'
        self.gas_used = int.from_bytes(log[2:10], 'little')
        self.return_value = log[10:].hex()
        self.slot = slot

    def decode(self, tx: {}):
        self._set_defaults()
        meta_ixs = tx['meta']['innerInstructions']
        msg = tx['transaction']['message']
        msg_ixs = msg["instructions"]
        accounts = msg['accountKeys']

        evm_ix_idxs = []
        for idx, ix in enumerate(msg_ixs):
            if accounts[ix["programIdIndex"]] == EVM_LOADER_ID:
                evm_ix_idxs.append(idx)

        for inner_ix in meta_ixs:
            if inner_ix["index"] in evm_ix_idxs:
                for event in inner_ix['instructions']:
                    if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                        log = base58.b58decode(event['data'])
                        evm_ix = int().from_bytes(log[:1], "little") # int(log[0])
                        if evm_ix == 7:
                            self._decode_event(log, inner_ix['index'])
                        elif evm_ix == 6:
                            self._decode_return(log, tx['slot'])
        return None


    def clear(self):
        self._set_defaults()

    def is_valid(self):
        return (self.slot != -1) and (not self.error)


class NeonTxAddrInfo:
    def __init__(self, rlp_sign=None, rlp_data=None):
        if not isinstance(rlp_sign, bytes) or not isinstance(rlp_data, bytes):
            self._set_defaults()
        else:
            self.decode(rlp_sign, rlp_data)

    def __str__(self):
        return str_fmt_object(self)

    def _set_defaults(self):
        self.addr = None
        self.sign = None
        self.rlp_tx = None
        self.error = None

    def decode(self, rlp_sign: bytes, rlp_data: bytes):
        self._set_defaults()
        try:
            tx = rlp.decode(rlp_data, EthTx)

            v = int(rlp_sign[64]) + 35 + 2 * tx[6]
            r = big_endian_to_int(rlp_sign[0:32])
            s = big_endian_to_int(rlp_sign[32:64])

            rlp_tx = rlp.encode(EthTx(tx[0], tx[1], tx[2], tx[3], tx[4], tx[5], v, r, s), EthTx)
            self.sign = '0x' + sha3(rlp_tx).hex()
            self.addr = w3.eth.account.recover_transaction(rlp_tx).lower()
            self.rlp_tx = rlp_tx.hex()
            return None

        except Exception as e:
            self.error = e
            return self.error

    def clear(self):
        self._set_defaults()

    def is_valid(self):
        return (self.addr is not None) and (not self.error)


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
            acc_list.append(str(some_pubkey))
            offset += 32

        return acc_list
    else:
        logger.debug("Not empty other")
        return None




class LogDB:
    def __init__(self):
        POSTGRES_DB = os.environ.get("POSTGRES_DB", "neon-db")
        POSTGRES_USER = os.environ.get("POSTGRES_USER", "neon-proxy")
        POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "neon-proxy-pass")
        POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")

        self.conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )

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
            UNIQUE(transactionLogIndex, transactionHash, topic)
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
            cur.executemany('INSERT INTO logs VALUES (%s, %s, %s, %s,  %s, %s,  %s) ON CONFLICT DO NOTHING', rows)
            self.conn.commit()
        else:
            logger.debug("NO LOGS")


    def get_logs(self, fromBlock = None, toBlock = None, address = None, topics = None, blockHash = None):
        queries = []
        params = []

        if fromBlock is not None:
            queries.append("blockNumber >= %s")
            params.append(fromBlock)

        if toBlock is not None:
            queries.append("blockNumber <= %s")
            params.append(toBlock)

        if blockHash is not None:
            blockHash = blockHash.lower()
            queries.append("blockHash = %s")
            params.append(blockHash)

        if topics is not None and len(topics) > 0:
            topics = [item.lower() for item in topics]
            query_placeholder = ", ".join(["%s" for _ in range(len(topics))])
            topics_query = f"topic IN ({query_placeholder})"

            queries.append(topics_query)
            params += topics

        if address is not None:
            if isinstance(address, str):
                address = address.lower()
                queries.append("address = %s")
                params.append(address)
            elif isinstance(address, list) and len(address) > 0:
                address = [item.lower() for item in address]
                query_placeholder = ", ".join(["%s" for _ in range(len(address))])
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

        self.client = Client(SOLANA_URL)

        self.operator = self.signer.public_key()
        self.operator_token = get_associated_token_address(PublicKey(self.operator), ETH_TOKEN_MINT_ID)


    def call(self, *args):
        try:
            cmd = ["solana",
                   "--url", SOLANA_URL,
                   ] + list(args)
            logger.debug(cmd)
            return subprocess.check_output(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            logger.debug("ERR: solana error {}".format(err))
            raise


    def unlock_accounts(self, blocked_storages):
        readonly_accs = [
            PublicKey(EVM_LOADER_ID),
            ETH_TOKEN_MINT_ID,
            PublicKey(TOKEN_PROGRAM_ID),
            PublicKey(SYSVAR_CLOCK_PUBKEY),
            PublicKey(SYSVAR_INSTRUCTION_PUBKEY),
            PublicKey(KECCAK_PROGRAM),
            PublicKey(SYSVAR_RENT_PUBKEY),
            PublicKey(INCINERATOR_PUBKEY),
            PublicKey(SYS_PROGRAM_ID),
        ]
        for storage, trx_accs in blocked_storages.items():
            (eth_trx, blocked_accs) = trx_accs
            acc_list = get_account_list(self.client, storage)
            if eth_trx is None:
                logger.error("trx is None")
                continue
            if blocked_accs is None:
                logger.error("blocked_accs is None")
                continue
            if acc_list is None:
                logger.error("acc_list is None. Storage is empty")
                logger.error(storage)
                continue

            eth_trx = rlp.decode(bytes.fromhex(eth_trx), EthTrx)
            if acc_list != blocked_accs:
                logger.error("acc_list != blocked_accs")
                continue

            if acc_list is not None:
                keys = [
                        AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                        AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=acc_list[4], is_signer=False, is_writable=True),
                        AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False)
                    ]
                for acc in acc_list:
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=(False if acc in readonly_accs else True)))

                trx = Transaction()
                trx.add(TransactionInstruction(
                    program_id=EVM_LOADER_ID,
                    data=bytearray.fromhex("15") + eth_trx[0].to_bytes(8, 'little'),
                    keys=keys
                ))

                logger.debug("Send Cancel")
                try:
                    self.client.send_transaction(trx, self.signer, opts=TxOpts(preflight_commitment=Confirmed))
                except Exception as err:
                    logger.error(err)
                else:
                    logger.debug("Canceled")
                    logger.debug(acc_list)
