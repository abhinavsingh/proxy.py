import base58
import base64
import json
import logging
import os
import random
import re
import struct
import time
from datetime import datetime
from hashlib import sha256
from typing import NamedTuple, Optional, Union, Dict, Tuple
import psycopg2
import rlp
from base58 import b58decode, b58encode
from construct import Bytes, Int8ul, Int32ul, Int64ul
from construct import Struct as cStruct
from eth_keys import keys as eth_keys
import eth_utils

from sha3 import keccak_256
from web3.auto import w3

from solana.account import Account as SolanaAccount
from solana.blockhash import Blockhash
from solana.rpc.api import Client as SolanaClient, SendTransactionError
from solana.rpc.commitment import Commitment, Confirmed
from solana.rpc.types import TxOpts
from solana.sysvar import *
from solana.transaction import AccountMeta, Transaction, TransactionInstruction
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT
from solana._layouts.system_instructions import InstructionType as SystemInstructionType

from spl.token.constants import ACCOUNT_LEN, ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address, create_associated_token_account, transfer2, Transfer2Params

from ..environment import neon_cli, evm_loader_id, ETH_TOKEN_MINT_ID, COLLATERAL_POOL_BASE, read_elf_params
from ..common_neon.utils import get_from_dict
from ..common_neon.errors import *
from .eth_proto import Trx
from ..core.acceptor.pool import new_acc_id_glob, acc_list_glob
from ..indexer.sql_dict import POSTGRES_USER, POSTGRES_HOST, POSTGRES_DB, POSTGRES_PASSWORD

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


NEW_USER_AIRDROP_AMOUNT = int(os.environ.get("NEW_USER_AIRDROP_AMOUNT", "0"))
location_bin = ".deploy_contract.bin"
confirmation_check_delay = float(os.environ.get("NEON_CONFIRMATION_CHECK_DELAY", "0.1"))
USE_COMBINED_START_CONTINUE = os.environ.get("USE_COMBINED_START_CONTINUE", "NO") == "YES"
CONTINUE_COUNT_FACTOR = int(os.environ.get("CONTINUE_COUNT_FACTOR", "3"))
TIMEOUT_TO_RELOAD_NEON_CONFIG = int(os.environ.get("TIMEOUT_TO_RELOAD_NEON_CONFIG", "3600"))
MINIMAL_GAS_PRICE=int(os.environ.get("MINIMAL_GAS_PRICE", 1))*10**9

ACCOUNT_SEED_VERSION=b'\1'

COLLATERALL_POOL_MAX=10

EMPTY_STORAGE_TAG=0

sysvarclock = "SysvarC1ock11111111111111111111111111111111"
sysinstruct = "Sysvar1nstructions1111111111111111111111111"
keccakprog = "KeccakSecp256k11111111111111111111111111111"
rentid = "SysvarRent111111111111111111111111111111111"
incinerator = "1nc1nerator11111111111111111111111111111111"
system = "11111111111111111111111111111111"

STORAGE_SIZE = 128 * 1024

ACCOUNT_INFO_LAYOUT = cStruct(
    "type" / Int8ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul,
    "trx_count" / Bytes(8),
    "code_account" / Bytes(32),
    "is_rw_blocked" / Int8ul,
    "rw_blocked_acc" / Bytes(32),
    "eth_token_account" / Bytes(32),
    "ro_blocked_cnt" / Int8ul,
)

CODE_INFO_LAYOUT = cStruct(
    "tag" / Int8ul,
    "owner" / Bytes(20),
    "code_size" / Bytes(4),
)

CREATE_ACCOUNT_LAYOUT = cStruct(
    "lamports" / Int64ul,
    "space" / Int64ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul
)

obligatory_accounts = [
    AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
    AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
    AccountMeta(pubkey=sysvarclock, is_signer=False, is_writable=False),
]

EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))


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

class CostSingleton(object):
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(CostSingleton, cls).__new__(cls)
            cls.instance.operator_cost = SQLCost()
        return cls.instance

class PermanentAccounts:
    def __init__(self, client, signer):
        while True:
            with new_acc_id_glob.get_lock():
                try:
                    self.acc_id = acc_list_glob.pop(0)
                except IndexError:
                    self.acc_id = new_acc_id_glob.value
                    new_acc_id_glob.value += 1

            logger.debug("LOCK RESOURCES {}".format(self.acc_id))

            self.operator = signer.public_key()
            self.operator_token = getTokenAddr(self.operator)

            acc_id_bytes = self.acc_id.to_bytes((self.acc_id.bit_length() + 7) // 8, 'big')

            storage_seed = keccak_256(b"storage" + acc_id_bytes).hexdigest()[:32]
            storage_seed = bytes(storage_seed, 'utf8')

            holder_seed = keccak_256(b"holder" + acc_id_bytes).hexdigest()[:32]
            holder_seed = bytes(holder_seed, 'utf8')

            try:
                self.storage, self.holder = create_multiple_accounts_with_seed(
                        client,
                        funding=signer,
                        base=signer,
                        seeds=[storage_seed, holder_seed],
                        sizes=[STORAGE_SIZE, STORAGE_SIZE]
                    )
            except Exception as err:
                logger.warn("Account is locked err({}) id({}) owner({})".format(str(err), self.acc_id, signer.public_key()))
            else:
                break

    def __del__(self):
        logger.debug("FREE RESOURCES {}".format(self.acc_id))
        with new_acc_id_glob.get_lock():
            acc_list_glob.append(self.acc_id)


class TransactionInfo:
    def __init__(self, caller_token, eth_accounts, eth_trx):
        self.eth_trx = eth_trx

        self.caller_token = caller_token
        self.eth_accounts = eth_accounts
        self.nonce = eth_trx.nonce

        hash = keccak_256(eth_trx.unsigned_msg()).digest()
        collateral_pool_index = int().from_bytes(hash[:4], "little") % COLLATERALL_POOL_MAX
        self.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')
        self.collateral_pool_address = create_collateral_pool_address(collateral_pool_index)


class AccountInfo(NamedTuple):
    ether: eth_keys.PublicKey
    trx_count: int
    code_account: PublicKey

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.ether, cont.trx_count, PublicKey(cont.code_account))


def create_account_layout(lamports, space, ether, nonce):
    return bytes.fromhex("02000000")+CREATE_ACCOUNT_LAYOUT.build(dict(
        lamports=lamports,
        space=space,
        ether=ether,
        nonce=nonce
    ))


def write_holder_layout(nonce, offset, data):
    return (bytes.fromhex('12')+
            nonce.to_bytes(8, byteorder='little')+
            offset.to_bytes(4, byteorder='little')+
            len(data).to_bytes(8, byteorder='little')+
            data)


def get_account_info(client, storage_account):
    opts = {
        "encoding": "base64",
        "commitment": "confirmed",
        "dataSlice": {
            "offset": 0,
            "length": 16,
        }
    }

    result = client._provider.make_request("getAccountInfo", str(storage_account), opts)
    logger.debug("\n{}".format(json.dumps(result, indent=4, sort_keys=True)))

    info = result['result']['value']
    if info is None:
        logger.debug("Can't get information about {}".format(storage_account))
        return None

    data = base64.b64decode(info['data'][0])

    account_tag = data[0]
    lamports = info['lamports']
    owner = info['owner']

    return (account_tag, lamports, owner)


def accountWithSeed(base, seed, program):
    result = PublicKey(sha256(bytes(base) + bytes(seed) + bytes(program)).digest())
    logger.debug('accountWithSeed %s', str(result))
    return result


def createAccountWithSeedTrx(funding, base, seed, lamports, space, program):
    seed_str = str(seed, 'utf8')
    data = SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type = SystemInstructionType.CREATE_ACCOUNT_WITH_SEED,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed_str), chars=seed_str),
                lamports=lamports,
                space=space,
                program_id=bytes(program)
            )
        )
    )
    logger.debug("createAccountWithSeedTrx %s %s %s", type(base), base, data.hex())
    created = accountWithSeed(base, seed, PublicKey(program))
    logger.debug("created %s", created)
    return TransactionInstruction(
        keys=[
            AccountMeta(pubkey=funding, is_signer=True, is_writable=True),
            AccountMeta(pubkey=created, is_signer=False, is_writable=True),
            AccountMeta(pubkey=base, is_signer=True, is_writable=False),
        ],
        program_id=system,
        data=data
    )


def create_collateral_pool_address(collateral_pool_index):
    COLLATERAL_SEED_PREFIX = "collateral_seed_"
    seed = COLLATERAL_SEED_PREFIX + str(collateral_pool_index)
    return accountWithSeed(PublicKey(COLLATERAL_POOL_BASE), str.encode(seed), PublicKey(evm_loader_id))


def create_account_with_seed(client, funding, base, seed, storage_size, eth_trx=None):
    account = accountWithSeed(base.public_key(), seed, PublicKey(evm_loader_id))

    if client.get_balance(account, commitment=Confirmed)['result']['value'] == 0:
        minimum_balance = client.get_minimum_balance_for_rent_exemption(storage_size, commitment=Confirmed)["result"]
        logger.debug("Minimum balance required for account {}".format(minimum_balance))

        trx = Transaction()
        trx.add(createAccountWithSeedTrx(funding.public_key(), base.public_key(), seed, minimum_balance, storage_size, PublicKey(evm_loader_id)))
        send_transaction(client, trx, funding, eth_trx=eth_trx, reason='createAccountWithSeed')

    return account


def create_multiple_accounts_with_seed(client, funding, base, seeds, sizes):
    accounts = []
    trx = Transaction()

    for seed, storage_size in zip(seeds, sizes):
        account = accountWithSeed(base.public_key(), seed, PublicKey(evm_loader_id))
        accounts.append(account)

        minimum_balance = client.get_minimum_balance_for_rent_exemption(storage_size, commitment=Confirmed)["result"]

        account_info = get_account_info(client, account)
        if account_info is None:
            logger.debug("Minimum balance required for account {}".format(minimum_balance))

            trx.add(createAccountWithSeedTrx(funding.public_key(), base.public_key(), seed, minimum_balance, storage_size, PublicKey(evm_loader_id)))
        else:
            (tag, lamports, owner) = account_info
            if lamports < minimum_balance:
                raise Exception("insufficient balance")
            if PublicKey(owner) != PublicKey(evm_loader_id):
                raise Exception("wrong owner")
            if tag != EMPTY_STORAGE_TAG:
                raise Exception("not empty")

    if len(trx.instructions) > 0:
        send_transaction(client, trx, funding)

    return accounts


def make_keccak_instruction_data(check_instruction_index, msg_len, data_start):
    if check_instruction_index > 255 and check_instruction_index < 0:
        raise Exception("Invalid index for instruction - {}".format(check_instruction_index))

    check_count = 1
    eth_address_size = 20
    signature_size = 65
    eth_address_offset = data_start
    signature_offset = eth_address_offset + eth_address_size
    message_data_offset = signature_offset + signature_size

    data = struct.pack("B", check_count)
    data += struct.pack("<H", signature_offset)
    data += struct.pack("B", check_instruction_index)
    data += struct.pack("<H", eth_address_offset)
    data += struct.pack("B", check_instruction_index)
    data += struct.pack("<H", message_data_offset)
    data += struct.pack("<H", msg_len)
    data += struct.pack("B", check_instruction_index)

    return data


class EthereumError(Exception):
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data

    def getError(self):
        error = {'code': self.code, 'message': self.message}
        if self.data: error['data'] = self.data
        return error


class EthereumAddress:
    def __init__(self, data, private=None):
        if isinstance(data, str):
            data = bytes(bytearray.fromhex(data[2:]))
        self.data = data
        self.private = private

    @staticmethod
    def random():
        letters = '0123456789abcdef'
        data = bytearray.fromhex(''.join([random.choice(letters) for k in range(64)]))
        pk = eth_keys.PrivateKey(data)
        return EthereumAddress(pk.public_key.to_canonical_address(), pk)

    def __str__(self):
        return '0x'+self.data.hex()

    def __repr__(self):
        return self.__str__()

    def __bytes__(self): return self.data


def emulator(contract, sender, data, value):
    data = data or "none"
    value = value or ""
    return neon_cli().call("emulate", sender, contract, data, value)


def confirm_transaction(client, tx_sig, confirmations=0):
    """Confirm a transaction."""
    TIMEOUT = 30  # 30 seconds  pylint: disable=invalid-name
    elapsed_time = 0
    while elapsed_time < TIMEOUT:
        logger.debug('confirm_transaction for %s', tx_sig)
        resp = client.get_signature_statuses([tx_sig])
        logger.debug('confirm_transaction: %s', resp)
        if resp["result"]:
            status = resp['result']['value'][0]
            if status and (status['confirmationStatus'] == 'finalized' or \
               status['confirmationStatus'] == 'confirmed' and status['confirmations'] >= confirmations):
                return
        time.sleep(confirmation_check_delay)
        elapsed_time += confirmation_check_delay
    raise RuntimeError("could not confirm transaction: ", tx_sig)


def solana2ether(public_key):
    from web3 import Web3
    return bytes(Web3.keccak(bytes.fromhex(public_key))[-20:])


def ether2program(ether):
    if isinstance(ether, str):
        pass
    elif isinstance(ether, EthereumAddress):
        ether = str(ether)
    else:
        ether = ether.hex()
    output = neon_cli().call("create-program-address", ether)
    items = output.rstrip().split(' ')
    return items[0], int(items[1])


def ether2seed(ether, program_id, base):
    if isinstance(ether, str):
        if ether.startswith('0x'): ether = ether[2:]
    else: ether = ether.hex()
    seed = b58encode(bytes.fromhex(ether))
    acc = accountWithSeed(base, seed, PublicKey(program_id))
    logger.debug('ether2program: {} {} => {} (seed {})'.format(ether, 255, acc, seed))
    return acc, 255, seed


def neon_config_load(ethereum_model):
    try:
        ethereum_model.neon_config_dict
    except AttributeError:
        logger.debug("loading the neon config dict for the first time!")
        ethereum_model.neon_config_dict = dict()
    else:
        elapsed_time = datetime.now().timestamp() - ethereum_model.neon_config_dict['load_time']
        logger.debug('elapsed_time={} proxy_id={}'.format(elapsed_time, ethereum_model.proxy_id))
        if elapsed_time < TIMEOUT_TO_RELOAD_NEON_CONFIG:
            return

    read_elf_params(ethereum_model.neon_config_dict)
    ethereum_model.neon_config_dict['load_time'] = datetime.now().timestamp()
    # 'Neon/v0.3.0-rc0-d1e4ff618457ea9cbc82b38d2d927e8a62168bec
    ethereum_model.neon_config_dict['web3_clientVersion'] = 'Neon/v' + \
                                                            ethereum_model.neon_config_dict['NEON_PKG_VERSION'] + \
                                                            '-' \
                                                            + ethereum_model.neon_config_dict['NEON_REVISION']
    logger.debug(ethereum_model.neon_config_dict)


def call_emulated(contract_id, caller_id, data=None, value=None):
    output = emulator(contract_id, caller_id, data, value)
    logger.debug("call_emulated %s %s %s %s return %s", contract_id, caller_id, data, value, output)
    result = json.loads(output)
    exit_status = result['exit_status']
    if exit_status == 'revert':
        result_value = result['result']
        if len(result_value) < 8 or result_value[:8] != '08c379a0':
            raise EthereumError(code=3, message='execution reverted')

        offset = int(result_value[8:8+64], 16)
        length = int(result_value[8+64:8+64+64], 16)
        message = str(bytes.fromhex(result_value[8+offset*2+64:8+offset*2+64+length*2]), 'utf8')
        raise EthereumError(code=3, message='execution reverted: '+message, data='0x'+result_value)
    if result["exit_status"] != "succeed":
        raise Exception("evm emulator error ", result)
    return result


def extract_measurements_from_receipt(receipt):
    log_messages = receipt['result']['meta']['logMessages']
    transaction = receipt['result']['transaction']
    accounts = transaction['message']['accountKeys']
    instructions = []
    for instr in transaction['message']['instructions']:
        program = accounts[instr['programIdIndex']]
        instructions.append({
            'accs': [accounts[acc] for acc in instr['accounts']],
            'program': accounts[instr['programIdIndex']],
            'data': b58decode(instr['data']).hex()
        })

    pattern = re.compile('Program ([0-9A-Za-z]+) (.*)')
    messages = []
    for log in log_messages:
        res = pattern.match(log)
        if res:
            (program, reason) = res.groups()
            if reason == 'invoke [1]': messages.append({'program':program,'logs':[]})
        messages[-1]['logs'].append(log)

    for instr in instructions:
        if instr['program'] in ('KeccakSecp256k11111111111111111111111111111',): continue
        if messages[0]['program'] != instr['program']:
            raise Exception('Invalid program in log messages: expect %s, actual %s' % (messages[0]['program'], instr['program']))
        instr['logs'] = messages.pop(0)['logs']
        exit_result = re.match(r'Program %s (success)'%instr['program'], instr['logs'][-1])
        if not exit_result: raise Exception("Can't get exit result")
        instr['result'] = exit_result.group(1)

        if instr['program'] == evm_loader_id:
            memory_result = re.match(r'Program log: Total memory occupied: ([0-9]+)', instr['logs'][-3])
            instruction_result = re.match(r'Program %s consumed ([0-9]+) of ([0-9]+) compute units'%instr['program'], instr['logs'][-2])
            if not (memory_result and instruction_result):
                raise Exception("Can't parse measurements for evm_loader")
            instr['measurements'] = {
                    'instructions': instruction_result.group(1),
                    'memory': memory_result.group(1)
                }

    result = []
    for instr in instructions:
        if instr['program'] == evm_loader_id:
            result.append({
                    'program':instr['program'],
                    'measurements':instr['measurements'],
                    'result':instr['result'],
                    'data':instr['data']
                })
    return result

# Do not rename this function! This name used in CI measurements (see function `cleanup_docker` in .buildkite/steps/deploy-test.sh)
def get_measurements(result):
    try:
        measurements = extract_measurements_from_receipt(result)
        for m in measurements: logger.info(json.dumps(m))
    except Exception as err:
        logger.error("Can't get measurements %s"%err)
        logger.info("Failed result: %s"%json.dumps(result, indent=3))


def send_transaction(client, trx, signer, eth_trx=None, reason=None):
    result = client.send_transaction(trx, signer, opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed))
    confirm_transaction(client, result["result"])
    result = client.get_confirmed_transaction(result["result"])
    update_transaction_cost(result, eth_trx, reason=reason)
    return result


def send_measured_transaction(client, trx, signer, eth_trx, reason):
    result = send_transaction(client, trx, signer, eth_trx=eth_trx, reason=reason)
    get_measurements(result)
    return result


def check_if_program_exceeded_instructions(err_result):
    err_instruction = "Program failed to complete: exceeded maximum number of instructions allowed"
    err_budget = "failed: Computational budget exceeded"

    if err_result['data']['logs'][-1].find(err_instruction) >= 0 or \
        err_result['data']['logs'][-2].find(err_instruction) >= 0 or \
        err_result['data']['logs'][-1].find(err_budget) >= 0:
        return True
    return False


def check_if_continue_returned(result):
    tx_info = result['result']
    accounts = tx_info["transaction"]["message"]["accountKeys"]
    evm_loader_instructions = []

    for idx, instruction in enumerate(tx_info["transaction"]["message"]["instructions"]):
        if accounts[instruction["programIdIndex"]] == evm_loader_id:
            evm_loader_instructions.append(idx)

    for inner in (tx_info['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == evm_loader_id:
                    instruction = base58.b58decode(event['data'])[:1]
                    if int().from_bytes(instruction, "little") == 6:  # OnReturn evmInstruction code
                        return (True, tx_info['transaction']['signatures'][0])
    return (False, ())


def call_continue(signer, client, perm_accs, trx_info, steps):
    try:
        return call_continue_iterative(signer, client, perm_accs, trx_info, steps)
    except Exception as err:
        logger.debug("call_continue_iterative exception:")
        logger.debug(str(err))

    return sol_instr_21_cancel(signer, client, perm_accs, trx_info)


def call_continue_iterative(signer, client, perm_accs, trx_info, step_count):
    while True:
        logger.debug("Continue iterative step:")
        result = sol_instr_10_continue(signer, client, perm_accs, trx_info, step_count)
        (succeed, signature) = check_if_continue_returned(result)
        if succeed:
            return signature


def sol_instr_10_continue(signer, client, perm_accs, trx_info, initial_step_count):
    step_count = initial_step_count
    while step_count > 0:
        trx = Transaction()
        trx.add(make_continue_instruction(signer, perm_accs, trx_info, step_count))

        logger.debug("Step count {}".format(step_count))
        try:
            result = send_measured_transaction(client, trx, signer, trx_info.eth_trx, 'ContinueV02')
            return result
        except SendTransactionError as err:
            if check_if_program_exceeded_instructions(err.result):
                step_count = int(step_count * 90 / 100)
            else:
                raise
    raise Exception("Can't execute even one EVM instruction")


def sol_instr_21_cancel(signer, client, perm_accs, trx_info):
    operator = signer.public_key()
    operator_token = getTokenAddr(operator)

    trx = Transaction()
    trx.add(TransactionInstruction(
        program_id=evm_loader_id,
        data=bytearray.fromhex("15") + trx_info.nonce.to_bytes(8, 'little'),
        keys=[
            AccountMeta(pubkey=perm_accs.storage, is_signer=False, is_writable=True),
            AccountMeta(pubkey=operator, is_signer=True, is_writable=True),
            AccountMeta(pubkey=operator_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=trx_info.caller_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=incinerator, is_signer=False, is_writable=True),
            AccountMeta(pubkey=system, is_signer=False, is_writable=False),

        ] + trx_info.eth_accounts + [

            AccountMeta(pubkey=sysinstruct, is_signer=False, is_writable=False),
        ] + obligatory_accounts
    ))

    logger.debug("Cancel")
    result = send_measured_transaction(client, trx, signer, trx_info.eth_trx, 'CancelWithNonce')
    return result['result']['transaction']['signatures'][0]


def make_partial_call_instruction(signer, perm_accs, trx_info, step_count, call_data):
    operator = signer.public_key()
    operator_token = getTokenAddr(operator)

    return TransactionInstruction(
        program_id = evm_loader_id,
        data = bytearray.fromhex("13") + trx_info.collateral_pool_index_buf + step_count.to_bytes(8, byteorder="little") + call_data,
        keys = [
            AccountMeta(pubkey=perm_accs.storage, is_signer=False, is_writable=True),

            AccountMeta(pubkey=sysinstruct, is_signer=False, is_writable=False),
            AccountMeta(pubkey=operator, is_signer=True, is_writable=True),
            AccountMeta(pubkey=trx_info.collateral_pool_address, is_signer=False, is_writable=True),
            AccountMeta(pubkey=operator_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=trx_info.caller_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=system, is_signer=False, is_writable=False),

        ] + trx_info.eth_accounts + [

            AccountMeta(pubkey=sysinstruct, is_signer=False, is_writable=False),
        ] + obligatory_accounts
        )


def make_continue_instruction(signer, perm_accs, trx_info, step_count, index=None):
    operator = signer.public_key()
    operator_token = getTokenAddr(operator)

    data = bytearray.fromhex("14") + trx_info.collateral_pool_index_buf + step_count.to_bytes(8, byteorder="little")
    if index:
        data = data + index.to_bytes(8, byteorder="little")

    return TransactionInstruction(
        program_id = evm_loader_id,
        data = data,
        keys = [
            AccountMeta(pubkey=perm_accs.storage, is_signer=False, is_writable=True),

            AccountMeta(pubkey=operator, is_signer=True, is_writable=True),
            AccountMeta(pubkey=trx_info.collateral_pool_address, is_signer=False, is_writable=True),
            AccountMeta(pubkey=operator_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=trx_info.caller_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=system, is_signer=False, is_writable=False),

        ] + trx_info.eth_accounts + [

            AccountMeta(pubkey=sysinstruct, is_signer=False, is_writable=False),
        ] + obligatory_accounts
    )


def make_call_from_account_instruction(signer, perm_accs, trx_info, step_count = 0):
    operator = signer.public_key()
    operator_token = getTokenAddr(operator)

    return TransactionInstruction(
        program_id = evm_loader_id,
        data = bytearray.fromhex("16") + trx_info.collateral_pool_index_buf + step_count.to_bytes(8, byteorder="little"),
        keys = [
            AccountMeta(pubkey=perm_accs.holder, is_signer=False, is_writable=True),
            AccountMeta(pubkey=perm_accs.storage, is_signer=False, is_writable=True),

            AccountMeta(pubkey=operator, is_signer=True, is_writable=True),
            AccountMeta(pubkey=trx_info.collateral_pool_address, is_signer=False, is_writable=True),
            AccountMeta(pubkey=operator_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=trx_info.caller_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=system, is_signer=False, is_writable=False),

        ] + trx_info.eth_accounts + [

            AccountMeta(pubkey=sysinstruct, is_signer=False, is_writable=False),
        ] + obligatory_accounts
    )


def make_05_call_instruction(signer, trx_info, call_data):
    operator = signer.public_key()
    operator_token = getTokenAddr(operator)

    return TransactionInstruction(
        program_id = evm_loader_id,
        data = bytearray.fromhex("05") + trx_info.collateral_pool_index_buf + call_data,
        keys = [
            AccountMeta(pubkey=sysinstruct, is_signer=False, is_writable=False),
            AccountMeta(pubkey=operator, is_signer=True, is_writable=True),
            AccountMeta(pubkey=trx_info.collateral_pool_address, is_signer=False, is_writable=True),
            AccountMeta(pubkey=operator_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=trx_info.caller_token, is_signer=False, is_writable=True),
            AccountMeta(pubkey=system, is_signer=False, is_writable=False),

        ] + trx_info.eth_accounts + obligatory_accounts
    )


def update_transaction_cost(receipt, eth_trx, extra_sol_trx=False, reason=None):
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
        if accounts[instruction["programIdIndex"]] == evm_loader_id:
            evm_loader_instructions.append(idx)

    for inner in (tx_info['meta']['innerInstructions']):
        if inner["index"] in evm_loader_instructions:
            for event in inner['instructions']:
                if accounts[event['programIdIndex']] == evm_loader_id:
                    used_gas = base58.b58decode(event['data'])[2:10]
                    used_gas = int().from_bytes(used_gas, "little")

    table = CostSingleton().operator_cost
    table.insert(
        hash,
        cost,
        used_gas if used_gas else 0,
        sender,
        to_address,
        sig,
        'extra' if extra_sol_trx else 'ok',
        reason if reason else ''
    )


def create_account_list_by_emulate(signer, client, eth_trx):
    sender_ether = bytes.fromhex(eth_trx.sender())
    add_keys_05 = []
    trx = Transaction()

    if not eth_trx.toAddress:
        to_address_arg = "deploy"
        to_address = keccak_256(rlp.encode((bytes.fromhex(eth_trx.sender()), eth_trx.nonce))).digest()[-20:]
    else:
        to_address_arg = eth_trx.toAddress.hex()
        to_address = eth_trx.toAddress

    output_json = call_emulated(to_address_arg, sender_ether.hex(), eth_trx.callData.hex(), hex(eth_trx.value))
    logger.debug("emulator returns: %s", json.dumps(output_json, indent=3))

    # resize storage account
    resize_instr = []
    for acc_desc in output_json["accounts"]:
        if acc_desc["new"] == False:

            if acc_desc.get("code_size_current") is not None and acc_desc.get("code_size") is not None:
                if acc_desc["code_size"] > acc_desc["code_size_current"]:
                    code_size = acc_desc["code_size"] + 2048
                    seed = b58encode(ACCOUNT_SEED_VERSION + os.urandom(20))
                    code_account_new = accountWithSeed(signer.public_key(), seed, PublicKey(evm_loader_id))

                    logger.debug("creating new code_account with increased size %s", code_account_new)
                    create_account_with_seed(client, signer, signer, seed, code_size, eth_trx);
                    logger.debug("resized account is created %s", code_account_new)

                    resize_instr.append(TransactionInstruction(
                        keys=[
                            AccountMeta(pubkey=PublicKey(acc_desc["account"]), is_signer=False, is_writable=True),
                            (
                                AccountMeta(pubkey=acc_desc["contract"], is_signer=False, is_writable=True)
                                if acc_desc["contract"] else
                                AccountMeta(pubkey=PublicKey("11111111111111111111111111111111"), is_signer=False, is_writable=False)
                            ),
                            AccountMeta(pubkey=code_account_new, is_signer=False, is_writable=True),
                            AccountMeta(pubkey=signer.public_key(), is_signer=True, is_writable=False)
                        ],
                        program_id=evm_loader_id,
                        data=bytearray.fromhex("11")+bytes(seed) # 17- ResizeStorageAccount
                    ))
                    # replace code_account
                    acc_desc["contract"] = code_account_new

    for instr in resize_instr:
        logger.debug("code and storage migration, account %s from  %s to %s", instr.keys[0].pubkey, instr.keys[1].pubkey, instr.keys[2].pubkey)

        tx = Transaction().add(instr)
        success = False
        count = 0

        while count < 2:
            logger.debug("attemt: %d", count)

            send_transaction(client, tx, signer, eth_trx=eth_trx, reason='resize_storage_account')
            info = _getAccountData(client, instr.keys[0].pubkey, ACCOUNT_INFO_LAYOUT.sizeof())
            info_data = AccountInfo.frombytes(info)
            if info_data.code_account == instr.keys[2].pubkey:
                success = True
                logger.debug("successful code and storage migration, %s", instr.keys[0].pubkey)
                break
            time.sleep(1)
            count = count+1

        if success == False:
            raise Exception("Can't resize storage account. Account is blocked {}".format(instr.keys[0].pubkey))

    for acc_desc in output_json["accounts"]:
        address = bytes.fromhex(acc_desc["address"][2:])

        code_account = None
        code_account_writable = False
        if acc_desc["new"]:
            logger.debug("Create solana accounts for %s: %s %s", acc_desc["address"], acc_desc["account"], acc_desc["contract"])
            if acc_desc["code_size"]:
                seed = b58encode(ACCOUNT_SEED_VERSION+address)
                code_account = accountWithSeed(signer.public_key(), seed, PublicKey(evm_loader_id))
                logger.debug("     with code account %s", code_account)
                code_size = acc_desc["code_size"] + 2048
                code_account_balance = client.get_minimum_balance_for_rent_exemption(code_size)["result"]
                trx.add(createAccountWithSeedTrx(signer.public_key(), signer.public_key(), seed, code_account_balance, code_size, PublicKey(evm_loader_id)))
                code_account_writable = acc_desc["writable"]

            extend_trx_with_create_and_airdrop(signer, EthereumAddress(address), code_account, trx=trx)

        if address == to_address:
            contract_sol = PublicKey(acc_desc["account"])
            if acc_desc["new"]:
                code_sol = code_account
                code_writable = code_account_writable
            else:
                if acc_desc["contract"] != None:
                    code_sol = PublicKey(acc_desc["contract"])
                    code_writable = acc_desc["writable"]
                else:
                    code_sol = None
                    code_writable = None

        elif address == sender_ether:
            sender_sol = PublicKey(acc_desc["account"])
        else:
            add_keys_05.append(AccountMeta(pubkey=acc_desc["account"], is_signer=False, is_writable=True))
            token_account = get_associated_token_address(PublicKey(acc_desc["account"]), ETH_TOKEN_MINT_ID)
            add_keys_05.append(AccountMeta(pubkey=token_account, is_signer=False, is_writable=True))
            if acc_desc["new"]:
                if code_account:
                    add_keys_05.append(AccountMeta(pubkey=code_account, is_signer=False, is_writable=code_account_writable))
            else:
                if acc_desc["contract"]:
                    add_keys_05.append(AccountMeta(pubkey=acc_desc["contract"], is_signer=False, is_writable=acc_desc["writable"]))

    for token_account in output_json["token_accounts"]:
        add_keys_05.append(AccountMeta(pubkey=PublicKey(token_account["key"]), is_signer=False, is_writable=True))

        if token_account["new"]:
            trx.add(createERC20TokenAccountTrx(signer, token_account))

    for account_meta in output_json["solana_accounts"]:
        add_keys_05.append(AccountMeta(pubkey=PublicKey(account_meta["pubkey"]), is_signer=account_meta["is_signer"], is_writable=account_meta["is_writable"]))

    caller_token = get_associated_token_address(PublicKey(sender_sol), ETH_TOKEN_MINT_ID)

    eth_accounts = [
            AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=get_associated_token_address(contract_sol, ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
        ] + ([AccountMeta(pubkey=code_sol, is_signer=False, is_writable=code_writable)] if code_sol != None else []) + [
            AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=caller_token, is_signer=False, is_writable=True),
        ] + add_keys_05

    trx_info = TransactionInfo(caller_token, eth_accounts, eth_trx)

    return trx_info, sender_ether, trx


def call_signed(signer, client, eth_trx, steps):

    (trx_info, sender_ether, create_acc_trx) = create_account_list_by_emulate(signer, client, eth_trx)

    call_iterative = False
    call_from_holder = False

    if not eth_trx.toAddress:
        call_from_holder = True
    else:
        msg = sender_ether + eth_trx.signature() + eth_trx.unsigned_msg()

        try:
            logger.debug("Try single trx call")
            return call_signed_noniterative(signer, client, eth_trx, trx_info, msg, create_acc_trx)
        except Exception as err:
            logger.debug(str(err))
            errStr = str(err)
            if "Program failed to complete" in errStr or "Computational budget exceeded" in errStr:
                logger.debug("Program exceeded instructions")
                call_iterative = True
            elif str(err).startswith("transaction too large:"):
                logger.debug("Transaction too large, call call_signed_with_holder_acc():")
                call_from_holder = True
            else:
                raise

    perm_accs = PermanentAccounts(client, signer)
    try:
        if call_iterative:
            try:
                return call_signed_iterative(signer, client, eth_trx, perm_accs, trx_info, steps, msg, create_acc_trx)
            except Exception as err:
                logger.debug(str(err))
                if str(err).startswith("transaction too large:"):
                    logger.debug("Transaction too large, call call_signed_with_holder_acc():")
                    call_from_holder = True
                else:
                    raise

        if call_from_holder:
            return call_signed_with_holder_acc(signer, client, eth_trx, perm_accs, trx_info, steps, create_acc_trx)
    finally:
        del perm_accs


def call_signed_iterative(signer, client, eth_trx, perm_accs, trx_info, steps, msg, create_acc_trx):
    if len(create_acc_trx.instructions):
        precall_txs = Transaction()
        precall_txs.add(create_acc_trx)
        send_measured_transaction(client, precall_txs, signer, eth_trx, 'CreateAccountsForTrx')

    precall_txs = Transaction()
    precall_txs.add(TransactionInstruction(
        program_id=keccakprog,
        data=make_keccak_instruction_data(len(precall_txs.instructions)+1, len(eth_trx.unsigned_msg()), data_start=13),
        keys=[
            AccountMeta(pubkey=keccakprog, is_signer=False, is_writable=False),
        ]))
    precall_txs.add(make_partial_call_instruction(signer, perm_accs, trx_info, 0, msg))

    logger.debug("Partial call")
    send_measured_transaction(client, precall_txs, signer, eth_trx, 'PartialCallFromRawEthereumTXv02')

    return call_continue(signer, client, perm_accs, trx_info, steps)


def call_signed_noniterative(signer, client, eth_trx, trx_info, msg, create_acc_trx):
    call_txs_05 = Transaction()
    call_txs_05.add(create_acc_trx)
    call_txs_05.add(TransactionInstruction(
        program_id=keccakprog,
        data=make_keccak_instruction_data(len(call_txs_05.instructions)+1, len(eth_trx.unsigned_msg()), 5),
        keys=[
            AccountMeta(pubkey=keccakprog, is_signer=False, is_writable=False),
        ]))
    call_txs_05.add(make_05_call_instruction(signer, trx_info, msg))
    result = send_measured_transaction(client, call_txs_05, signer, eth_trx, 'CallFromRawEthereumTX')
    return result['result']['transaction']['signatures'][0]


def call_signed_with_holder_acc(signer, client, eth_trx, perm_accs, trx_info, steps, create_acc_trx):

    write_trx_to_holder_account(signer, client, perm_accs.holder, perm_accs.acc_id, eth_trx)
    if len(create_acc_trx.instructions):
        precall_txs = Transaction()
        precall_txs.add(create_acc_trx)
        send_measured_transaction(client, precall_txs, signer, eth_trx, 'create_accounts_for_deploy')

    precall_txs = Transaction()
    precall_txs.add(make_call_from_account_instruction(signer, perm_accs, trx_info))

    # ExecuteTrxFromAccountDataIterative
    logger.debug("ExecuteTrxFromAccountDataIterative:")
    send_measured_transaction(client, precall_txs, signer, eth_trx, 'ExecuteTrxFromAccountDataIterativeV02')

    return call_continue(signer, client, perm_accs, trx_info, steps)


def createERC20TokenAccountTrx(signer, token_info):
    trx = Transaction()
    trx.add(TransactionInstruction(
    program_id=evm_loader_id,
    data=bytes.fromhex('0F'),
    keys=[
        AccountMeta(pubkey=signer.public_key(), is_signer=True, is_writable=True),
        AccountMeta(pubkey=PublicKey(token_info["key"]), is_signer=False, is_writable=True),
        AccountMeta(pubkey=PublicKey(token_info["owner"]), is_signer=False, is_writable=True),
        AccountMeta(pubkey=PublicKey(token_info["contract"]), is_signer=False, is_writable=True),
        AccountMeta(pubkey=PublicKey(token_info["mint"]), is_signer=False, is_writable=True),
        AccountMeta(pubkey=system, is_signer=False, is_writable=False),
        AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        AccountMeta(pubkey=rentid, is_signer=False, is_writable=False),
    ]))

    return trx


def write_trx_to_holder_account(signer, client, holder, acc_id, eth_trx):
    msg = eth_trx.signature() + len(eth_trx.unsigned_msg()).to_bytes(8, byteorder="little") + eth_trx.unsigned_msg()

    # Write transaction to transaction holder account
    offset = 0
    receipts = []
    rest = msg
    while len(rest):
        (part, rest) = (rest[:1000], rest[1000:])
        trx = Transaction()
        # logger.debug("sender_sol %s %s %s", sender_sol, holder, acc.public_key())
        trx.add(TransactionInstruction(program_id=evm_loader_id,
                                       data=write_holder_layout(acc_id, offset, part),
                                       keys=[
                                           AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                                           AccountMeta(pubkey=signer.public_key(), is_signer=True, is_writable=False),
                                       ]))
        receipts.append(client.send_transaction(trx, signer,
                opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed))["result"])
        offset += len(part)
    logger.debug("receipts %s", receipts)
    for rcpt in receipts:
        confirm_transaction(client, rcpt)
        result = client.get_confirmed_transaction(rcpt)
        update_transaction_cost(result, eth_trx, reason='WriteHolder')
        logger.debug("confirmed: %s", rcpt)


def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account, commitment=Confirmed)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) < expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data


def getAccountInfo(client, eth_account: EthereumAddress):
    account_sol, nonce = ether2program(eth_account)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)


def getLamports(client, eth_account):
    pda_account, nonce = ether2program(eth_account)
    return int(client.get_balance(pda_account, commitment=Confirmed)['result']['value'])


def make_create_eth_account_trx(signer: SolanaAccount, eth_address: EthereumAddress, evm_loader_id, code_acc=None) \
                                -> Tuple[Transaction, PublicKey]:

    solana_address, nonce = ether2program(eth_address)
    token_acc_address = get_associated_token_address(PublicKey(solana_address), ETH_TOKEN_MINT_ID)
    logger.debug(f'Create eth account: {eth_address}, sol account: {solana_address}, token_acc_address: {token_acc_address}, nonce: {nonce}')

    base = signer.public_key()
    data = bytes.fromhex('02000000') + CREATE_ACCOUNT_LAYOUT.build(dict(lamports=0,
                                                                        space=0,
                                                                        ether=bytes(eth_address),
                                                                        nonce=nonce))
    trx = Transaction()
    if code_acc is None:
        trx.add(TransactionInstruction(
            program_id=evm_loader_id,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(solana_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=token_acc_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=system, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=rentid, is_signer=False, is_writable=False),
            ]))
    else:
        trx.add(TransactionInstruction(
            program_id=evm_loader_id,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(solana_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=token_acc_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
                AccountMeta(pubkey=system, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=rentid, is_signer=False, is_writable=False),
            ]))
    return trx, token_acc_address


def make_transfer_instruction(owner_pda_account: SolanaAccount, associated_token_account: PublicKey) -> TransactionInstruction:
    owner_pda_address = owner_pda_account.public_key()
    owner_associated_token_account = getTokenAddr(owner_pda_address)
    transfer_instruction = transfer2(Transfer2Params(source=owner_associated_token_account,
                                                     owner=owner_pda_address,
                                                     dest=associated_token_account,
                                                     amount=NEW_USER_AIRDROP_AMOUNT * eth_utils.denoms.gwei,
                                                     decimals=9,
                                                     mint=ETH_TOKEN_MINT_ID,
                                                     program_id=TOKEN_PROGRAM_ID))
    logger.debug(f"Token transfer from token: {owner_associated_token_account}, owned by: {owner_pda_address}, to token: "
                 f"{associated_token_account}, owned by: {associated_token_account} , value: {NEW_USER_AIRDROP_AMOUNT}")
    return transfer_instruction


def extend_trx_with_create_and_airdrop(signer: SolanaAccount, eth_account: EthereumAddress, code_acc=None, *, trx):
    create_trx, associated_token_account = make_create_eth_account_trx(signer, eth_account, evm_loader_id, code_acc)
    trx.add(create_trx)
    if NEW_USER_AIRDROP_AMOUNT <= 0:
        return
    transfer_instruction = make_transfer_instruction(signer, associated_token_account)
    trx.add(transfer_instruction)


def create_eth_account_and_airdrop(client: SolanaClient, signer: SolanaAccount, eth_account: EthereumAddress):
    trx = Transaction()
    extend_trx_with_create_and_airdrop(signer, eth_account, trx=trx)
    result = send_transaction(client, trx, signer)
    error = result.get("error")
    if error is not None:
        logger.error(f"Failed to create eth_account and airdrop: {eth_account}, error occurred: {error}")
        raise Exception("Create eth_account error")


def get_token_balance_gwei(client: SolanaClient, pda_account: str) -> int:
    associated_token_account = get_associated_token_address(PublicKey(pda_account), ETH_TOKEN_MINT_ID)
    rpc_response = client.get_token_account_balance(associated_token_account, commitment=Confirmed)
    error = rpc_response.get('error')
    if error is not None:
        message = error.get("message")
        if message == SolanaErrors.AccountNotFound.value:
            raise SolanaAccountNotFoundError()
        logger.error(f"Failed to get_token_balance_gwei by associated_token_account: {associated_token_account}, "
                     f"got get_token_account_balance error: \"{message}\"")
        raise Exception("Getting balance error")

    balance = get_from_dict(rpc_response, "result", "value", "amount")
    if balance is None:
        logger.error(f"Failed to get_token_balance_gwei by associated_token_account: {associated_token_account}, response: {rpc_response}")
        raise Exception("Unexpected get_balance response")
    return int(balance)


def get_token_balance_or_airdrop(client: SolanaClient, signer: SolanaAccount, eth_account: EthereumAddress) -> int:
    associated_token_account, nonce = ether2program(eth_account)
    logger.debug(f"Get balance for eth account: {eth_account} aka: {associated_token_account}")

    try:
        return get_token_balance_gwei(client, associated_token_account)
    except SolanaAccountNotFoundError:
        logger.debug(f"Account not found:  {eth_account} aka: {associated_token_account} - create")
        create_eth_account_and_airdrop(client, signer, eth_account)
        return get_token_balance_gwei(client, associated_token_account)


def getTokenAddr(account):
    return get_associated_token_address(PublicKey(account), ETH_TOKEN_MINT_ID)


def make_instruction_data_from_tx(instruction, private_key=None):
    if isinstance(instruction, dict):
        if instruction.get('chainId') is None:
            raise Exception("chainId value is needed in input dict")
        if private_key is None:
            raise Exception("Needed private key for transaction creation from fields")

        signed_tx = w3.eth.account.sign_transaction(instruction, private_key)
        # logger.debug(signed_tx.rawTransaction.hex())
        _trx = Trx.fromString(signed_tx.rawTransaction)
        # logger.debug(json.dumps(_trx.__dict__, cls=JsonEncoder, indent=3))

        raw_msg = _trx.get_msg(instruction['chainId'])
        sig = keys.Signature(vrs=[1 if _trx.v % 2 == 0 else 0, _trx.r, _trx.s])
        pub = sig.recover_public_key_from_msg_hash(_trx.hash())

        # logger.debug(pub.to_hex())

        return (pub.to_canonical_address(), sig.to_bytes(), raw_msg)
    elif isinstance(instruction, str):
        if instruction[:2] == "0x":
            instruction = instruction[2:]

        _trx = Trx.fromString(bytearray.fromhex(instruction))
        # logger.debug(json.dumps(_trx.__dict__, cls=JsonEncoder, indent=3))

        raw_msg = _trx.get_msg()
        sig = keys.Signature(vrs=[1 if _trx.v % 2 == 0 else 0, _trx.r, _trx.s])
        pub = sig.recover_public_key_from_msg_hash(_trx.hash())

        data = pub.to_canonical_address()
        data += sig.to_bytes()
        data += raw_msg

        return (pub.to_canonical_address(), sig.to_bytes(), raw_msg)
    else:
        raise Exception("function gets ")


def is_account_exists(client: SolanaClient, eth_account: EthereumAddress) -> bool:
    pda_account, nonce = ether2program(eth_account)
    info = client.get_account_info(pda_account, commitment=Confirmed)
    value = get_from_dict(info, "result", "value")
    return value is not None


def estimate_gas(client: SolanaClient, signer: SolanaAccount, contract_id: str, caller_eth_account: EthereumAddress,
                 data: str = None, value: str = None):
    if not is_account_exists(client, caller_eth_account):
        create_eth_account_and_airdrop(client, signer, caller_eth_account)
    result = call_emulated(contract_id, str(caller_eth_account), data, value)
    used_gas = result.get("used_gas")
    if used_gas is None:
        logger.error(f"Failed estimate_gas, unexpected result, by contract_id: {contract_id}, caller_eth_account: "
                     f"{caller_eth_account}, data: {data}, value: {value}, emulation result: {result}")
        raise Exception("Bad estimate_gas result")
    return used_gas + EXTRA_GAS
