from __future__ import annotations

import base64
import multiprocessing
import psycopg2
import statistics

from typing import NamedTuple

from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from logged_groups import logged_group
from typing import Dict, Union, Callable

from ..common_neon.address import ether2program
from ..common_neon.layouts import STORAGE_ACCOUNT_INFO_LAYOUT, CODE_ACCOUNT_INFO_LAYOUT, ACCOUNT_INFO_LAYOUT
from ..common_neon.utils import get_from_dict

from ..environment import INDEXER_LOG_SKIP_COUNT

from .pg_common import POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST
from .pg_common import encode, decode


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

    def get_req_id(self):
        return f"{self.idx}{self.sign}"[:7]



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


class MetricsToLogBuff :
    def __init__(self):
        self._reset()

    def _reset(self):
        self.counter = 0
        self.items_list = {}
        self.items_latest = {}

    def print(self, logger: Callable[[str], None], list_params: Dict[str, Union[int, float]], latest_params: Dict[str, int]):
        for key, value in list_params.items():
            metric_list = self.items_list.setdefault(key, [])
            metric_list.append(value)
        for key, value in latest_params.items():
            self.items_latest[key] = value
        self.counter += 1

        if self.counter % INDEXER_LOG_SKIP_COUNT != 0:
            return

        msg = ''
        for key, value_list in self.items_list.items():
            msg += f' {key} avg: {statistics.mean(value_list):.2f}'
            msg += f' min: {min(value_list):.2f}'
            msg += f' max: {max(value_list):.2f};'
        for key, value in self.items_latest.items():
            msg += f' {key}: {value};'
        logger(msg)
        self._reset()


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
