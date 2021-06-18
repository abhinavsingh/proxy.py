from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from solana.sysvar import *
from solana.blockhash import Blockhash
import time
import subprocess
import os
import base64
from base58 import b58encode, b58decode
from eth_keys import keys as eth_keys
from typing import NamedTuple
import random
import json
from sha3 import keccak_256
import struct
import rlp
from .eth_proto import Trx
from solana.rpc.types import TxOpts
import re
from solana.rpc.commitment import Commitment, Confirmed
from solana.rpc.api import SendTransactionError

from construct import Bytes, Int8ul, Int32ul, Int64ul, Struct as cStruct
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType as SystemInstructionType
from hashlib import sha256
#from eth_keys import keys
from web3.auto import w3
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
evm_loader_id = os.environ.get("EVM_LOADER")
# evm_loader_id = "8TUNjkF7R4nAM6mEYL3zDe1G9wQq6wrHCYz1VDtYnhGt"
location_bin = ".deploy_contract.bin"

sysvarclock = "SysvarC1ock11111111111111111111111111111111"
sysinstruct = "Sysvar1nstructions1111111111111111111111111"
keccakprog = "KeccakSecp256k11111111111111111111111111111"
rentid = "SysvarRent111111111111111111111111111111111"
system = "11111111111111111111111111111111"

ACCOUNT_INFO_LAYOUT = cStruct(
    "tag" / Int8ul,
    "eth_acc" / Bytes(20),
    "nonce" / Int8ul,
    "trx_count" / Bytes(8),
    "code_acc" / Bytes(32),
    "is_blocked" / Int8ul,
    "blocked_by" / Bytes(32),
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

class AccountInfo(NamedTuple):
    eth_acc: eth_keys.PublicKey
    trx_count: int

    @staticmethod
    def frombytes(data):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.eth_acc, cont.trx_count)

def create_account_layout(lamports, space, ether, nonce):
    return bytes.fromhex("02000000")+CREATE_ACCOUNT_LAYOUT.build(dict(
        lamports=lamports,
        space=space,
        ether=ether,
        nonce=nonce
    ))

def write_layout(offset, data):
    return (bytes.fromhex("00000000")+
            offset.to_bytes(4, byteorder="little")+
            len(data).to_bytes(8, byteorder="little")+
            data)

def accountWithSeed(base, seed, program):
    #logger.debug(type(base), str(base), type(seed), str(seed), type(program), str(program))
    result = PublicKey(sha256(bytes(base)+bytes(seed)+bytes(program)).digest())
    logger.debug('accountWithSeed %s', str(result))
    return result

def createAccountWithSeed(funding, base, seed, lamports, space, program):
    seed_str = str(seed, 'utf8')
    data = SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type = SystemInstructionType.CreateAccountWithSeed,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed_str), chars=seed_str),
                lamports=lamports,
                space=space,
                program_id=bytes(program)
            )
        )
    )
    logger.debug("createAccountWithSeed %s %s %s", type(base), base, data.hex())
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

def create_storage_account(client, funding, base, seed):
    storage = accountWithSeed(base.public_key(), seed, PublicKey(evm_loader_id))

    if client.get_balance(storage, commitment=Confirmed)['result']['value'] == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(funding.public_key(), base.public_key(), seed, 10**9, 128*1024, PublicKey(evm_loader_id)))
        send_transaction(client, trx, funding)

    return storage

def make_keccak_instruction_data(check_instruction_index, msg_len, data_start = 1):
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


def emulator(contract, sender, data):
    cmd = 'emulate --commitment=recent  --evm_loader {} {} {} {}'.format(evm_loader_id, sender, contract, data)
    print(cmd)
    return neon_cli().call(cmd)


class solana_cli:
    def call(self, arguments):
        cmd = 'solana --url {} {}'.format(solana_url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            logger.debug("ERR: solana error {}".format(err))
            raise

class neon_cli:
    def call(self, arguments):
        cmd = 'neon-cli --url {} {}'.format(solana_url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            logger.debug("ERR: neon-cli error {}".format(err))
            raise

def confirm_transaction(client, tx_sig, confirmations=1):
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
#            logger.debug('Confirmed transaction:', resp)
                return
        sleep_time = 1
        time.sleep(sleep_time)
        elapsed_time += sleep_time
    #if not resp["result"]:
    raise RuntimeError("could not confirm transaction: ", tx_sig)
    #return resp

def solana2ether(public_key):
    from web3 import Web3
    return bytes(Web3.keccak(bytes.fromhex(public_key))[-20:])

def ether2program(ether, program_id, base):
    if isinstance(ether, str):
        if ether.startswith('0x'): ether = ether[2:]
    else: ether = ether.hex()
    output = neon_cli().call("create-program-address {} --evm_loader {}".format(ether, program_id))
    items = output.rstrip().split(' ')
    return (items[0], int(items[1]))

def ether2seed(ether, program_id, base):
    if isinstance(ether, str):
        if ether.startswith('0x'): ether = ether[2:]
    else: ether = ether.hex()
    seed = b58encode(bytes.fromhex(ether))
    acc = accountWithSeed(base, seed, PublicKey(program_id))
    logger.debug('ether2program: {} {} => {} (seed {})'.format(ether, 255, acc, seed))
    return (acc, 255, seed)

def call_emulated(contract_id, caller_id, data):
    output = emulator(contract_id, caller_id, data)
    logger.debug("call_emulated %s %s %s return %s", contract_id, caller_id, data, output)
    result = json.loads(output)
    exit_status = result['exit_status']
    if exit_status == 'revert':
        offset = int(result['result'][8:8+64], 16)
        length = int(result['result'][8+64:8+64+64], 16)
        message = str(bytes.fromhex(result['result'][8+offset*2+64:8+offset*2+64+length*2]), 'utf8')
        raise EthereumError(code=3, message='execution reverted: '+message, data='0x'+result['result'])
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

def send_transaction(client, trx, acc):
    result = client.send_transaction(trx, acc, opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed))
    confirm_transaction(client, result["result"])
    result = client.get_confirmed_transaction(result["result"])
    return result

def send_measured_transaction(client, trx, acc):
    result = send_transaction(client, trx, acc)
    get_measurements(result)
    return result

def check_if_program_exceeded_instructions(err_result):
    err_pattern = "Program failed to complete: exceeded maximum number of instructions allowed"
    if err_result['data']['logs'][-1].find(err_pattern) >= 0 or err_result['data']['logs'][-2].find(err_pattern) >= 0:
        return True
    return False

def check_if_continue_returned(result):
    # logger.debug(result)
    acc_meta_lst = result["result"]["transaction"]["message"]["accountKeys"]
    evm_loader_index = acc_meta_lst.index(evm_loader_id)

    innerInstruction = result['result']['meta']['innerInstructions']
    innerInstruction = next((i for i in innerInstruction if i["index"] == 0), None)
    if (innerInstruction and innerInstruction['instructions']):
        instruction = innerInstruction['instructions'][-1]
        if (instruction['programIdIndex'] == evm_loader_index):
            data = b58decode(instruction['data'])
            if (data[0] == 6):
                return (True, result['result']['transaction']['signatures'][0])
    return (False, ())

def call_continue_bucked(acc, client, step_count, accounts, continue_count):
    result_list = []
    for index in range(continue_count):
        trx = Transaction().add(make_continue_instruction(accounts, step_count, index))
        result = client.send_transaction(
                trx,
                acc,
                opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed)
            )["result"]
        result_list.append(result)
    for trx in result_list:
        confirm_transaction(client, trx)
        result = client.get_confirmed_transaction(trx)
        get_measurements(result)
        (finded, signature) = check_if_continue_returned(result)
        if finded:
            return signature
    return None

def call_continue_iterative(acc, client, step_count, accounts):
    try:
        while(True):
            result = sol_instr_10_continue(acc, client, step_count, accounts)
            (succed, signature) = check_if_continue_returned(result)
            if succed:
                return signature
    except Exception as err:
        sol_instr_12_cancel(acc, client, accounts)
        raise

def sol_instr_10_continue(acc, client, initial_step_count, accounts):
    step_count = initial_step_count
    while step_count > 0:
        trx = Transaction()
        trx.add(make_continue_instruction(accounts, step_count))

        print("Step count {}", step_count)
        try:
            result = send_measured_transaction(client, trx, acc)
            return result
        except SendTransactionError as err:
            if check_if_program_exceeded_instructions(err.result):
                step_count = int(step_count * 90 / 100)
            else:
                raise
    raise Exception("Can't execute even one EVM instruction")

def sol_instr_12_cancel(acc, client, accounts):
    trx = Transaction()
    trx.add(TransactionInstruction(program_id=evm_loader_id, data=bytearray.fromhex("0C"), keys=accounts))

    logger.debug("Cancel")
    result = send_measured_transaction(client, trx, acc)

def make_partial_call_instruction(accounts, step_count, call_data):
    return TransactionInstruction(program_id = evm_loader_id,
                            data = bytearray.fromhex("09") + step_count.to_bytes(8, byteorder="little") + call_data,
                            keys = accounts)

def make_continue_instruction(accounts, step_count, index=None):
    data = bytearray.fromhex("0A") + step_count.to_bytes(8, byteorder="little")
    if index:
        data = data + index.to_bytes(8, byteorder="little")

    return TransactionInstruction(program_id = evm_loader_id,
                            data = data,
                            keys = accounts)

def make_call_from_account_instruction(accounts, step_count = 0):
    return TransactionInstruction(program_id = evm_loader_id,
                            data = bytearray.fromhex("0B") + step_count.to_bytes(8, byteorder="little"),
                            keys = accounts)

def simulate_continue(acc, client, accounts, step_count):
    continue_count = 45
    while True:
        blockhash = Blockhash(client.get_recent_blockhash(Confirmed)["result"]["value"]["blockhash"])
        trx = Transaction(recent_blockhash = blockhash)
        for _ in range(continue_count):
            trx.add(make_continue_instruction(accounts, step_count))
        trx.sign(acc)

        try:
            trx.serialize()
        except Exception as err:
            logger.debug("trx.serialize() exception")
            if str(err).startswith("transaction too large:"):
                if continue_count == 0:
                    raise Exception("transaction too large")
                continue_count = int(continue_count * 90 / 100)
                continue
            raise

        response = client.simulate_transaction(trx, commitment=Confirmed)

        if response["result"]["value"]["err"]:
            instruction_error = response["result"]["value"]["err"]["InstructionError"]
            err = instruction_error[1]
            if isinstance(err, str) and (err == "ProgramFailedToComplete" or err == "ComputationalBudgetExceeded"):
                step_count = int(step_count * 90 / 100)
                if step_count == 0:
                    raise Exception("cant run even one instruction")
            elif isinstance(err, dict) and "Custom" in err:
                if continue_count == 0:
                    raise Exception("uninitialized storage account")
                continue_count = instruction_error[0]
            else:
                logger.debug("Result:\n%s"%json.dumps(response, indent=3))
                raise Exception("unspecified error")
        else:
            break

    logger.debug("tx_count = {}, step_count = {}".format(continue_count, step_count))
    return (continue_count, step_count)

def create_account_list_by_emulate(acc, client, ethTrx, storage):
    sender_ether = bytes.fromhex(ethTrx.sender())
    add_keys_05 = []
    trx = Transaction()

    output_json = call_emulated(ethTrx.toAddress.hex(), sender_ether.hex(), ethTrx.callData.hex())
    logger.debug("emulator returns: %s", json.dumps(output_json, indent=3))
    for acc_desc in output_json["accounts"]:

        address = bytes.fromhex(acc_desc["address"][2:])
        if address == ethTrx.toAddress:
            (contract_sol, code_sol) = (acc_desc["account"], acc_desc["contract"])
        elif address == sender_ether:
            sender_sol = (acc_desc["account"])
        else:
            add_keys_05.append(AccountMeta(pubkey=acc_desc["account"], is_signer=False, is_writable=acc_desc["writable"]))
            if acc_desc["contract"]:
                add_keys_05.append(AccountMeta(pubkey=acc_desc["contract"], is_signer=False, is_writable=acc_desc["writable"]))
        if acc_desc["new"]:
            logger.debug("Create solana accounts for %s: %s %s", acc_desc["address"], acc_desc["account"], acc_desc["contract"])
            code_account = None
            if acc_desc["code_size"]:
                seed = b58encode(address)
                code_account = accountWithSeed(acc.public_key(), seed, PublicKey(evm_loader_id))
                logger.debug("     with code account %s", code_account)
                trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), seed, 10 ** 9, acc_desc["code_size"] + 4 * 1024, PublicKey(evm_loader_id)))
                add_keys_05.append(AccountMeta(pubkey=code_account, is_signer=False, is_writable=acc_desc["writable"]))
            trx.add(createEtherAccountTrx(client, address, evm_loader_id, acc, code_account)[0])

    accounts = [
            AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
            AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=code_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),
            AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
        ] + add_keys_05 + [
            AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
    ]
    return (accounts, sender_ether, sender_sol, trx)

def call_signed(acc, client, ethTrx, storage, steps):

    (accounts, sender_ether, sender_sol, create_acc_trx) = create_account_list_by_emulate(acc, client, ethTrx, storage)
    msg = sender_ether + ethTrx.signature() + ethTrx.unsigned_msg()

# try call 05 call
        # if str(err).startswith("transaction too large"):
        #     logger.debug("Transaction too large, call call_signed_with_holder_acc():")
        #     return call_signed_with_holder_acc(acc, client, ethTrx, storage, steps, accounts, create_acc_trx)

    precall_txs = Transaction()
    precall_txs.add(create_acc_trx)
    precall_txs.add(TransactionInstruction(
        program_id=keccakprog,
        data=make_keccak_instruction_data(len(precall_txs.instructions)+1, len(ethTrx.unsigned_msg()), data_start=9),
        keys=[
            AccountMeta(pubkey=PublicKey(sender_sol), is_signer=False, is_writable=False),
        ]))
    precall_txs.add(make_partial_call_instruction(accounts, 0, msg))

    logger.debug("Partial call")
    send_measured_transaction(client, precall_txs, acc)

    while True:
        try:
            simulation_result = simulate_continue(acc, client, accounts, steps)
        except:
            logger.debug("Continue iterative:")
            return call_continue_iterative(acc, client, steps, accounts)
        else:
            (continue_count, instruction_count) = simulation_result
            logger.debug("Continue bucked:")
            signature = call_continue_bucked(acc, client, instruction_count, accounts, continue_count)
            if signature:
                return signature

def call_signed_with_holder_acc(acc, client, ethTrx, storage, steps, accounts, create_acc_trx):

    holder = write_trx_to_holder_account(acc, client, ethTrx)

    accounts.insert(0, AccountMeta(pubkey=holder, is_signer=False, is_writable=True))

    precall_txs = Transaction()
    precall_txs.add(create_acc_trx)
    precall_txs.add(make_call_from_account_instruction(accounts))

    # ExecuteTrxFromAccountDataIterative
    logger.debug("ExecuteTrxFromAccountDataIterative:")
    send_measured_transaction(client, precall_txs, acc)

    while True:
        try:
            simulation_result = simulate_continue(acc, client, accounts, steps)
        except Exception as err:
            logger.debug("Continue:")
            return call_continue_iterative(acc, client, steps, accounts[1:])
        else:
            (continue_count, instruction_count) = simulation_result
            logger.debug("Continue bucked:")
            signature = call_continue_bucked(acc, client, instruction_count, accounts[1:], continue_count)
            if signature:
                return signature


def createEtherAccountTrx(client, ether, evm_loader_id, signer, code_acc=None):
    if isinstance(ether, str):
        if ether.startswith('0x'): ether = ether[2:]
    else: ether = ether.hex()
    (sol, nonce) = ether2program(ether, evm_loader_id, signer.public_key())
    logger.debug('createEtherAccount: {} {} => {}'.format(ether, nonce, sol))
    seed = b58encode(bytes.fromhex(ether))
    base = signer.public_key()
    data=bytes.fromhex('02000000')+CREATE_ACCOUNT_LAYOUT.build(dict(
            lamports=10**9,
            space=0,
            ether=bytes.fromhex(ether),
            nonce=nonce))
    trx = Transaction()
    if code_acc is None:
        trx.add(TransactionInstruction(
            program_id=evm_loader_id,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
                AccountMeta(pubkey=system, is_signer=False, is_writable=False),
            ]))
    else:
        trx.add(TransactionInstruction(
            program_id=evm_loader_id,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
                AccountMeta(pubkey=system, is_signer=False, is_writable=False),
            ]))
    return (trx, sol)

def createEtherAccount(client, ether, evm_loader_id, signer, space=0):
    (trx, sol) = createEtherAccountTrx(client, ether, evm_loader_id, signer, space)
    result = send_transaction(client, trx, signer)
    logger.debug('createEtherAccount result: %s', result)
    return sol

def write_trx_to_holder_account(acc, client, ethTrx):
    # Create transaction holder account (if not exists)
    seed = bytes("1236", 'utf8')
    holder = PublicKey(
        sha256(bytes(acc.public_key()) + seed + bytes(PublicKey(evm_loader_id))).digest())
    logger.debug("Holder %s", holder)

    if client.get_balance(holder, commitment=Confirmed)['result']['value'] == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), seed, 10 ** 9, 128 * 1024,
                                      PublicKey(evm_loader_id)))
        result = send_measured_transaction(client, trx, acc)

    # Build deploy transaction
    msg = ethTrx.signature() + len(ethTrx.unsigned_msg()).to_bytes(8, byteorder="little") + ethTrx.unsigned_msg()
    # logger.debug("msg", msg.hex())

    # Write transaction to transaction holder account
    offset = 0
    receipts = []
    rest = msg
    while len(rest):
        (part, rest) = (rest[:1000], rest[1000:])
        trx = Transaction()
        # logger.debug("sender_sol %s %s %s", sender_sol, holder, acc.public_key())
        trx.add(TransactionInstruction(program_id=evm_loader_id,
                                       data=write_layout(offset, part),
                                       keys=[
                                           AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                                           AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
                                       ]))
        receipts.append(client.send_transaction(trx, acc,
                opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed))["result"])
        offset += len(part)
    logger.debug("receipts %s", receipts)
    for rcpt in receipts:
        confirm_transaction(client, rcpt)
        logger.debug("confirmed: %s", rcpt)

    return holder


def deploy_contract(acc, client, ethTrx, storage, steps):

    sender_ether = bytes.fromhex(ethTrx.sender())
    (sender_sol, _) = ether2program(sender_ether.hex(), evm_loader_id, acc.public_key())
    logger.debug("Sender account solana: %s %s", sender_ether, sender_sol)

    #info = _getAccountData(client, sender_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    #trx_count = int.from_bytes(AccountInfo.frombytes(info).trx_count, 'little')
    #logger.debug("Sender solana trx_count: %s", trx_count)

    # Create legacy contract address from (sender_eth, nonce)
    #rlp = pack(sender_ether, ethTrx.nonce or None)
    contract_eth = keccak_256(rlp.encode((sender_ether, ethTrx.nonce))).digest()[-20:]
    (contract_sol, contract_nonce) = ether2program(contract_eth.hex(), evm_loader_id, acc.public_key())
    (code_sol, code_nonce, code_seed) = ether2seed(contract_eth.hex(), evm_loader_id, acc.public_key())

    logger.debug("Legacy contract address ether: %s", contract_eth.hex())
    logger.debug("Legacy contract address solana: %s %s", contract_sol, contract_nonce)
    logger.debug("Legacy code address solana: %s %s", code_sol, code_nonce)

    holder = write_trx_to_holder_account(acc, client, ethTrx)

    # Create contract account & execute deploy transaction
    logger.debug("    # Create contract account & execute deploy transaction")
    trx = Transaction()
    sender_sol_info = client.get_account_info(sender_sol, commitment=Confirmed)
    if sender_sol_info['result']['value'] is None:
        trx.add(createEtherAccountTrx(client, sender_ether, evm_loader_id, acc)[0])

    if client.get_balance(code_sol, commitment=Confirmed)['result']['value'] == 0:
        msg_size = len(ethTrx.signature() + len(ethTrx.unsigned_msg()).to_bytes(8, byteorder="little") + ethTrx.unsigned_msg())
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), code_seed, 10**9, CODE_INFO_LAYOUT.sizeof()+msg_size+2048, PublicKey(evm_loader_id)))
    if client.get_balance(contract_sol, commitment=Confirmed)['result']['value'] == 0:
        trx.add(createEtherAccountTrx(client, contract_eth, evm_loader_id, acc, code_sol)[0])
    if len(trx.instructions):
        result = send_measured_transaction(client, trx, acc)

    accounts = [AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
                AccountMeta(pubkey=code_sol, is_signer=False, is_writable=True),
                AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
                AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
                AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
                ]
    
    continue_accounts = accounts[1:]

    init_trx = Transaction()
    init_trx.add(make_call_from_account_instruction(accounts))

    # ExecuteTrxFromAccountDataIterative
    logger.debug("ExecuteTrxFromAccountDataIterative:")
    send_measured_transaction(client, init_trx, acc)

    while True:
        try:
            simulation_result = simulate_continue(acc, client, accounts, steps, init_trx)
        except Exception as err:
            # Continue
            logger.debug("Continue:")
            signature = call_continue_iterative(acc, client, steps, continue_accounts)
            return (signature, '0x'+contract_eth.hex())
        else:
            (continue_count, instruction_count) = simulation_result
            # Continue
            logger.debug("Continue:")
            signature = call_continue_bucked(acc, client, instruction_count, continue_accounts, continue_count)
            if signature:
                return (signature, '0x'+contract_eth.hex())




def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account, commitment=Confirmed)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) != expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data

def getAccountInfo(client, eth_acc, base_account):
    (account_sol, nonce) = ether2program(bytes(eth_acc).hex(), evm_loader_id, base_account)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)

def getLamports(client, evm_loader, eth_acc, base_account):
    (account, nonce) = ether2program(bytes(eth_acc).hex(), evm_loader, base_account)
    return int(client.get_balance(account, commitment=Confirmed)['result']['value'])


def make_instruction_data_from_tx(instruction, private_key=None):
    if isinstance(instruction, dict):
        if instruction['chainId'] == None:
            raise Exception("chainId value is needed in input dict")
        if private_key == None:
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
