from __future__ import annotations

import base64
import multiprocessing
import psycopg2
import traceback

from typing import NamedTuple

from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_CLOCK_PUBKEY, SYSVAR_RENT_PUBKEY
from solana.transaction import AccountMeta, Transaction, TransactionInstruction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from logged_groups import logged_group

from ..common_neon.address import ether2program
from ..common_neon.constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT, ACCOUNT_INFO_LAYOUT
from ..common_neon.utils import get_from_dict
from ..environment import SOLANA_URL, EVM_LOADER_ID, ETH_TOKEN_MINT_ID, get_solana_accounts

from proxy.indexer.pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST
from proxy.indexer.pg_common import encode, decode


def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        return True
    return False


class SolanaIxSignInfo:
    def __init__(self, sign: str, slot: int, idx: int):
        self.sign = sign  # Solana transaction signature
        self.slot = slot  # Solana block slot
        self.idx  = idx   # Instruction index

    def __str__(self):
        return f'{self.slot} {self.sign} {self.idx}'

    def __hash__(self):
        return hash((self.sign, self.slot, self.idx))

    def __eq__(self, other):
        return (self.sign, self.slot, self.idx) == (other.sign, other.slot, other.idx)


@logged_group("neon.Indexer")
def get_accounts_from_storage(client, storage_account, *, logger):
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


@logged_group("neon.Indexer")
def get_accounts_by_neon_address(client: Client, neon_address, *, logger):
    pda_address, _nonce = ether2program(neon_address)
    reciept = client.get_account_info(pda_address, commitment=Confirmed)
    account_info = get_from_dict(reciept, 'result', 'value')
    if account_info is None:
        logger.debug(f"account_info is None for pda_address({pda_address}) in reciept({reciept})")
        return None, None
    data = base64.b64decode(account_info['data'][0])
    if len(data) < ACCOUNT_INFO_LAYOUT.sizeof():
        logger.debug(f"{len(data)} < {ACCOUNT_INFO_LAYOUT.sizeof()}")
        return None, None
    account = ACCOUNT_INFO_LAYOUT.parse(data)
    code_account = None
    if account.code_account != [0]*32:
        code_account = str(PublicKey(account.code_account))
    return pda_address, code_account


@logged_group("neon.Indexer")
def get_code_from_account(client: Client, address, *, logger):
    reciept = client.get_account_info(address, commitment=Confirmed)
    code_account_info = get_from_dict(reciept, 'result', 'value')
    if code_account_info is None:
        logger.debug(f"code_account_info is None for code_address({address}) in reciept({reciept})")
        return None
    data = base64.b64decode(code_account_info['data'][0])
    if len(data) < CODE_ACCOUNT_INFO_LAYOUT.sizeof():
        return None
    storage = CODE_ACCOUNT_INFO_LAYOUT.parse(data)
    offset = CODE_ACCOUNT_INFO_LAYOUT.sizeof()
    if len(data) < offset + storage.code_size:
        return None
    return '0x' + data[offset:][:storage.code_size].hex()


class DBQuery(NamedTuple):
    column_list: []
    key_list: []
    order_list: []


class DBQueryExpression(NamedTuple):
    column_expr: str
    where_expr: str
    where_keys: []
    order_expr: str


@logged_group("neon.Indexer")
class BaseDB:
    _create_table_lock = multiprocessing.Lock()

    def __init__(self):
        self._conn = psycopg2.connect(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOST
        )
        self._conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        with self._create_table_lock:
            cursor = self._conn.cursor()
            cursor.execute(self._create_table_sql())

    def _create_table_sql(self) -> str:
        assert False, 'No script for the table'

    def _build_expression(self, q: DBQuery) -> DBQueryExpression:

        return DBQueryExpression(
            column_expr=','.join(q.column_list),
            where_expr=' AND '.join(['1=1'] + [f'{name}=%s' for name, _ in q.key_list]),
            where_keys=[value for _, value in q.key_list],
            order_expr='ORDER BY ' + ', '.join(q.order_list) if len(q.order_list) else '',
        )

    def _fetchone(self, query: DBQuery) -> str:
        e = self._build_expression(query)

        request = f'''
            SELECT {e.column_expr}
              FROM {self._table_name} AS a
             WHERE {e.where_expr}
                   {e.order_expr}
             LIMIT 1
        '''

        with self._conn.cursor() as cursor:
            cursor.execute(request, e.where_keys)
            return cursor.fetchone()

    def __del__(self):
        self._conn.close()

    def decode_list(self, v):
        return [] if not v else decode(v)

    def encode_list(self, v: []):
        return None if (not v) or (len(v) == 0) else encode(v)


@logged_group("neon.Indexer")
class Canceller:
    def __init__(self):
        # Initialize user account
        self.signer = get_solana_accounts()[0]

        self.client = Client(SOLANA_URL)

        self.operator = self.signer.public_key()
        self.operator_token = get_associated_token_address(PublicKey(self.operator), ETH_TOKEN_MINT_ID)

    def unlock_accounts(self, blocked_storages):
        readonly_accs = [
            PublicKey(EVM_LOADER_ID),
            PublicKey(ETH_TOKEN_MINT_ID),
            PublicKey(TOKEN_PROGRAM_ID),
            PublicKey(SYSVAR_CLOCK_PUBKEY),
            PublicKey(SYSVAR_INSTRUCTION_PUBKEY),
            PublicKey(KECCAK_PROGRAM),
            PublicKey(SYSVAR_RENT_PUBKEY),
            PublicKey(INCINERATOR_PUBKEY),
            PublicKey(SYS_PROGRAM_ID),
        ]
        for storage, tx_accounts in blocked_storages.items():
            (neon_tx, blocked_accounts) = tx_accounts
            if blocked_accounts is None:
                self.error(f"Emtpy blocked accounts for the Neon tx {neon_tx}.")

            if blocked_accounts is not None:
                keys = [
                        AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=self.operator, is_signer=True, is_writable=True),
                        AccountMeta(pubkey=self.operator_token, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=blocked_accounts[4], is_signer=False, is_writable=True),
                        AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
                        AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False)
                    ]
                for acc in blocked_accounts:
                    is_writable = False if PublicKey(acc) in readonly_accs else True
                    keys.append(AccountMeta(pubkey=acc, is_signer=False, is_writable=is_writable))

                trx = Transaction()
                nonce = int(neon_tx.nonce, 16)
                trx.add(TransactionInstruction(
                    program_id=EVM_LOADER_ID,
                    data=bytearray.fromhex("15") + nonce.to_bytes(8, 'little'),
                    keys=keys
                ))

                self.debug("Send Cancel")
                try:
                    self.client.send_transaction(trx, self.signer, opts=TxOpts(preflight_commitment=Confirmed))
                except Exception as err:
                    err_tb = "".join(traceback.format_tb(err.__traceback__))
                    self.error('Exception on submitting transaction. ' +
                               f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
                else:
                    self.debug(f"Canceled: {blocked_accounts}")
