import base58
import psycopg2

from ..environment import EVM_LOADER_ID, WRITE_TRANSACTION_COST_IN_DB 
from ..indexer.sql_dict import POSTGRES_USER, POSTGRES_HOST, POSTGRES_DB, POSTGRES_PASSWORD

class SQLCost():
    def __init__(self):

        self.conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )

        self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = self.conn.cursor()
        cur.execute('''
                CREATE TABLE IF NOT EXISTS OPERATOR_COST
                (
                    id SERIAL PRIMARY KEY,
                    hash char(64),
                    cost bigint,
                    used_gas bigint,
                    sender char(40),
                    to_address char(40) ,
                    sig char(100),
                    status varchar(100),
                    reason varchar(100)
                )'''
                    )

    def close(self):
        self.conn.close()

    def insert(self, hash, cost, used_gas, sender, to_address, sig, status, reason):
        cur = self.conn.cursor()
        cur.execute('''
                INSERT INTO OPERATOR_COST (hash, cost, used_gas, sender, to_address, sig, status, reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ''',
            (hash, cost, used_gas, sender, to_address, sig, status, reason)
        )


operator_cost = SQLCost()


def update_transaction_cost(receipt, eth_trx, extra_sol_trx=False, reason=None):
    if not WRITE_TRANSACTION_COST_IN_DB:
        return

    cost = receipt['result']['meta']['preBalances'][0] - receipt['result']['meta']['postBalances'][0]
    if eth_trx:
        hash = eth_trx.hash_signed().hex()
        sender = eth_trx.sender()
        to_address = eth_trx.toAddress.hex() if eth_trx.toAddress else "None"
    else:
        hash = None
        sender = None
        to_address = None

    sig = receipt['result']['transaction']['signatures'][0]
    used_gas=None

    tx_info = receipt['result']
    accounts = tx_info["transaction"]["message"]["accountKeys"]
    evm_loader_instructions = []

    for idx, instruction in enumerate(tx_info["transaction"]["message"]["instructions"]):
        if accounts[instruction["programIdIndex"]] == EVM_LOADER_ID:
            evm_loader_instructions.append(idx)

    for inner in (tx_info['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == EVM_LOADER_ID:
                    used_gas = base58.b58decode(event['data'])[2:10]
                    used_gas = int().from_bytes(used_gas, "little")

    operator_cost.insert(
        hash,
        cost,
        used_gas if used_gas else 0,
        sender,
        to_address,
        sig,
        'extra' if extra_sol_trx else 'ok',
        reason if reason else ''
    )
