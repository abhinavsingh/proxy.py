import base64
import json
import os
import subprocess
import time
from enum import Enum
from hashlib import sha256
from typing import NamedTuple, Tuple, Union

import base58
import rlp
from base58 import b58encode
from construct import Bytes, Int8ul, Int64ul, Struct as cStruct
from eth_keys import keys as eth_keys
from sha3 import keccak_256
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType as SystemInstructionType
from solana.account import Account
from solana.publickey import PublicKey
from solana.rpc import types
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.transaction import AccountMeta, TransactionInstruction, Transaction

from spl.token.constants import TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, ACCOUNT_LEN
from spl.token.instructions import get_associated_token_address, approve, ApproveParams, create_associated_token_account
import base58
import math

CREATE_ACCOUNT_LAYOUT = cStruct(
    "ether" / Bytes(20),
    "nonce" / Int8ul
)

system = "11111111111111111111111111111111"
tokenkeg = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
sysvarclock = "SysvarC1ock11111111111111111111111111111111"
sysinstruct = "Sysvar1nstructions1111111111111111111111111"
keccakprog = "KeccakSecp256k11111111111111111111111111111"
rentid = "SysvarRent111111111111111111111111111111111"
incinerator = "1nc1nerator11111111111111111111111111111111"
collateral_pool_base = "4sW3SZDJB7qXUyCYKA7pFL8eCTfm3REr8oSiKkww7MaT"
COMPUTE_BUDGET_ID: PublicKey = PublicKey("ComputeBudget111111111111111111111111111111")

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
EVM_LOADER = os.environ.get("EVM_LOADER")
ETH_TOKEN_MINT_ID: PublicKey = PublicKey(os.environ.get("ETH_TOKEN_MINT"))

EVM_LOADER_SO = os.environ.get("EVM_LOADER_SO", 'target/bpfel-unknown-unknown/release/evm_loader.so')
client = Client(solana_url)
path_to_solana = 'solana'

ACCOUNT_SEED_VERSION = b'\1'

# amount of gas per 1 byte evm_storage
EVM_BYTE_COST = 6960  # 1_000_000_000/ 100 * 365 / (1024*1024) * 2
# number of evm steps per transaction
EVM_STEPS = 500
# the message size that is used to holder-account filling
HOLDER_MSG_SIZE = 950
# Ethereum account allocated data size
ACCOUNT_MAX_SIZE = 256
# spl-token account allocated data size
SPL_TOKEN_ACCOUNT_SIZE = 165
# payment to treasure
PAYMENT_TO_TREASURE = 5000
# payment for solana signature verification
LAMPORTS_PER_SIGNATURE = 5000
# account storage overhead for calculation of base rent
ACCOUNT_STORAGE_OVERHEAD = 128

DEFAULT_UNITS = 500 * 1000
DEFAULT_HEAP_FRAME = 256 * 1024
DEFAULT_ADDITIONAL_FEE = 0


class SplToken:
    def __init__(self, url):
        self.url = url

    def call(self, arguments):
        cmd = 'spl-token --url {} {}'.format(self.url, arguments)
        print('cmd:', cmd)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: spl-token error {}".format(err))
            raise

    def transfer(self, mint, amount, recipient):
        self.call("transfer {} {} {}".format(mint, amount, recipient))

    def balance(self, acc):
        from decimal import Decimal
        res = self.call("balance --address {}".format(acc))
        return Decimal(res.rstrip())

    def mint(self, mint_id, recipient, amount, owner=None):
        if owner is None:
            self.call("mint {} {} {}".format(mint_id, amount, recipient))
        else:
            self.call("mint {} {} {} --owner {}".format(mint_id, amount, recipient, owner))
        print("minting {} tokens for {}".format(amount, recipient))

    def create_token(self, owner=None):
        if owner is None:
            res = self.call("create-token")
        else:
            res = self.call("create-token --owner {}".format(owner))
        if not res.startswith("Creating token "):
            raise Exception("create token error")
        else:
            return res.split()[2]

    def create_token_account(self, token, owner=None):
        if owner is None:
            res = self.call("create-account {}".format(token))
        else:
            res = self.call("create-account {} --owner {}".format(token, owner))
        if not res.startswith("Creating account "):
            raise Exception("create account error %s" % res)
        else:
            return res.split()[2]


def create_collateral_pool_address(collateral_pool_index):
    COLLATERAL_SEED_PREFIX = "collateral_seed_"
    seed = COLLATERAL_SEED_PREFIX + str(collateral_pool_index)
    return accountWithSeed(PublicKey(collateral_pool_base), seed, PublicKey(EVM_LOADER))


def confirm_transaction(http_client, tx_sig, confirmations=0):
    """Confirm a transaction."""
    TIMEOUT = 30  # 30 seconds pylint: disable=invalid-name
    elapsed_time = 0
    while elapsed_time < TIMEOUT:
        print('confirm_transaction for %s', tx_sig)
        resp = http_client.get_signature_statuses([tx_sig])
        print('confirm_transaction: %s', resp)
        if resp["result"]:
            status = resp['result']['value'][0]
            if status and (status['confirmationStatus'] == 'finalized' or status['confirmationStatus'] == 'confirmed'
                           and status['confirmations'] >= confirmations):
                return
        sleep_time = 0.1
        time.sleep(sleep_time)
        elapsed_time += sleep_time
    raise RuntimeError("could not confirm transaction: ", tx_sig)


def accountWithSeed(base, seed, program):
    # print(type(base), type(seed), type(program))
    return PublicKey(sha256(bytes(base) + bytes(seed, 'utf8') + bytes(program)).digest())


def createAccountWithSeed(funding, base, seed, lamports, space, program):
    data = SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type=SystemInstructionType.CREATE_ACCOUNT_WITH_SEED,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed), chars=seed),
                lamports=lamports,
                space=space,
                program_id=bytes(program)
            )
        )
    )
    print("createAccountWithSeed", data.hex())
    created = accountWithSeed(base, seed, program)
    print("created", created)
    return TransactionInstruction(
        keys=[
            AccountMeta(pubkey=funding, is_signer=True, is_writable=True),
            AccountMeta(pubkey=created, is_signer=False, is_writable=True),
            AccountMeta(pubkey=base, is_signer=True, is_writable=False),
        ],
        program_id=system,
        data=data
    )


class solana_cli:
    def __init__(self, acc=None):
        self.acc = acc

    def call(self, arguments):
        cmd = ""
        if self.acc == None:
            cmd = '{} --url {} {}'.format(path_to_solana, solana_url, arguments)
        else:
            cmd = '{} --keypair {} --url {} {}'.format(path_to_solana, self.acc.get_path(), solana_url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: solana error {}".format(err))
            raise


class neon_cli:
    def __init__(self, verbose_flags=''):
        self.verbose_flags = verbose_flags

    def call(self, arguments):
        cmd = 'neon-cli {} --commitment=processed --url {} {} -vvv'.format(self.verbose_flags, solana_url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: neon-cli error {}".format(err))
            raise

    def emulate(self, loader_id, arguments):
        cmd = 'neon-cli {} --commitment=processed --evm_loader {} --url {} emulate {}'.format(self.verbose_flags,
                                                                                              loader_id,
                                                                                              solana_url,
                                                                                              arguments)
        print('cmd:', cmd)
        try:
            output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
            without_empty_lines = os.linesep.join([s for s in output.splitlines() if s])
            last_line = without_empty_lines.splitlines()[-1]
            return last_line
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: neon-cli error {}".format(err))
            raise


class RandomAccount:
    def __init__(self, path=None):
        if path == None:
            self.make_random_path()
            print("New keypair file: {}".format(self.path))
            self.generate_key()
        else:
            self.path = path
        self.retrieve_keys()
        print('New Public key:', self.acc.public_key())
        print('Private:', self.acc.secret_key())

    def make_random_path(self):
        self.path = os.urandom(5).hex() + ".json"

    def generate_key(self):
        cmd_generate = 'solana-keygen new --no-passphrase --outfile {}'.format(self.path)
        try:
            return subprocess.check_output(cmd_generate, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: solana error {}".format(err))
            raise

    def retrieve_keys(self):
        with open(self.path) as f:
            d = json.load(f)
            self.acc = Account(d[0:32])

    def get_path(self):
        return self.path

    def get_acc(self):
        return self.acc


class WalletAccount(RandomAccount):
    def __init__(self, path):
        self.path = path
        self.retrieve_keys()
        print('Wallet public key:', self.acc.public_key())


class OperatorAccount:
    def __init__(self, path=None):
        if path == None:
            self.path = operator1_keypair_path()
        else:
            self.path = path
        self.retrieve_keys()
        print('Public key:', self.acc.public_key())
        print('Private key:', self.acc.secret_key().hex())

    def retrieve_keys(self):
        with open(self.path) as f:
            d = json.load(f)
            self.acc = Account(d[0:32])

    def get_path(self):
        return self.path

    def get_acc(self):
        return self.acc


class EvmLoader:
    def __init__(self, acc: OperatorAccount, programId=EVM_LOADER):
        if programId == None:
            print("Load EVM loader...")
            result = json.loads(solana_cli(acc).call('deploy {}'.format(EVM_LOADER_SO)))
            programId = result['programId']
        EvmLoader.loader_id = programId
        print("Done\n")

        self.loader_id = EvmLoader.loader_id
        self.acc = acc
        print("Evm loader program: {}".format(self.loader_id))

    def airdropNeonTokens(self, user_ether_address: Union[str, bytes], amount: int) -> None:
        operator = self.acc.get_acc()

        (neon_evm_authority, _) = PublicKey.find_program_address([b"Deposit"], PublicKey(self.loader_id))
        pool_token_account = get_associated_token_address(neon_evm_authority, ETH_TOKEN_MINT_ID)
        source_token_account = get_associated_token_address(operator.public_key(), ETH_TOKEN_MINT_ID)
        (user_solana_address, _) = self.ether2program(user_ether_address)

        pool_account_exists = client.get_account_info(pool_token_account, commitment="processed")["result"][
                                  "value"] is not None
        print("Pool Account Exists: ", pool_account_exists)

        trx = TransactionWithComputeBudget()
        if not pool_account_exists:
            trx.add(create_associated_token_account(operator.public_key(), neon_evm_authority, ETH_TOKEN_MINT_ID))

        trx.add(approve(ApproveParams(
            program_id=TOKEN_PROGRAM_ID,
            source=source_token_account,
            delegate=neon_evm_authority,
            owner=operator.public_key(),
            amount=amount * (10 ** 9),
        )))
        trx.add(TransactionInstruction(
            program_id=self.loader_id,
            data=bytes.fromhex("19"),
            keys=[
                AccountMeta(pubkey=source_token_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=pool_token_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=user_solana_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=neon_evm_authority, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        ))
        result = send_transaction(client, trx, operator)
        print("Airdrop transaction: ", result)

    def deploy(self, contract_path, config=None):
        print('deploy contract')
        if config == None:
            output = neon_cli().call("deploy --evm_loader {} {}".format(self.loader_id, contract_path))
        else:
            output = neon_cli().call("deploy --evm_loader {} --config {} {}".format(self.loader_id, config,
                                                                                    contract_path))
        print(type(output), output)
        result = json.loads(output.splitlines()[-1])
        return result

    def createEtherAccount(self, ether):
        (trx, sol) = self.createEtherAccountTrx(ether)
        result = send_transaction(client, trx, self.acc.get_acc())
        print('result:', result)
        return sol

    def ether2seed(self, ether):
        if isinstance(ether, str):
            if ether.startswith('0x'): ether = ether[2:]
        else:
            ether = ether.hex()
        seed = b58encode(ACCOUNT_SEED_VERSION + bytes.fromhex(ether)).decode('utf8')
        acc = accountWithSeed(self.acc.get_acc().public_key(), seed, PublicKey(self.loader_id))
        print('ether2program: {} {} => {}'.format(ether, 255, acc))
        return (acc, 255)

    def ether2program(self, ether):
        if isinstance(ether, str):
            if ether.startswith('0x'): ether = ether[2:]
        else:
            ether = ether.hex()
        output = neon_cli().call("create-program-address --evm_loader {} {}".format(self.loader_id, ether))
        items = output.rstrip().split(' ')
        return items[0], int(items[1])

    def checkAccount(self, solana):
        info = client.get_account_info(solana)
        print("checkAccount({}): {}".format(solana, info))

    def deployChecked(self, location, caller, caller_ether):
        trx_count = getTransactionCount(client, caller)
        ether = keccak_256(rlp.encode((caller_ether, trx_count))).digest()[-20:]

        program = self.ether2program(ether)
        code = self.ether2seed(ether)
        info = client.get_account_info(program[0])
        if info['result']['value'] is None:
            res = self.deploy(location)
            return res['programId'], bytes.fromhex(res['ethereum'][2:]), res['codeId']
        elif info['result']['value']['owner'] != self.loader_id:
            raise Exception("Invalid owner for account {}".format(program))
        else:
            return program[0], ether, code[0]

    def createEtherAccountTrx(self, ether: Union[str, bytes], code_acc=None) -> Tuple[Transaction, str]:
        if isinstance(ether, str):
            if ether.startswith('0x'): ether = ether[2:]
        else:
            ether = ether.hex()

        (sol, nonce) = self.ether2program(ether)
        print('createEtherAccount: {} {} => {}'.format(ether, nonce, sol))

        base = self.acc.get_acc().public_key()
        data = bytes.fromhex('18') + CREATE_ACCOUNT_LAYOUT.build(dict(ether=bytes.fromhex(ether), nonce=nonce))
        trx = TransactionWithComputeBudget()
        if code_acc is None:
            trx.add(TransactionInstruction(
                program_id=self.loader_id,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=system, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
                ]))
        else:
            trx.add(TransactionInstruction(
                program_id=self.loader_id,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=system, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
                ]))
        return (trx, sol)


def getBalance(account):
    return client.get_balance(account, commitment=Confirmed)['result']['value']


ACCOUNT_INFO_LAYOUT = cStruct(
    "type" / Int8ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul,
    "tx_count" / Bytes(8),
    "balance" / Bytes(32),
    "code_account" / Bytes(32),
    "is_rw_blocked" / Int8ul,
    "ro_blocked_cnt" / Int8ul,
)


class AccountInfo(NamedTuple):
    ether: eth_keys.PublicKey
    tx_count: int
    code_account: PublicKey

    @staticmethod
    def frombytes(data: bytes):
        cont = ACCOUNT_INFO_LAYOUT.parse(data)
        return AccountInfo(cont.ether, cont.tx_count, PublicKey(cont.code_account))


def getAccountData(client: Client, account: Union[str, PublicKey], expected_length: int) -> bytes:
    info = client.get_account_info(account, commitment=Confirmed)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) < expected_length:
        print("len(data)({}) < expected_length({})".format(len(data), expected_length))
        raise Exception("Wrong data length for account data {}".format(account))
    return data


def getTransactionCount(client: Client, sol_account: Union[str, PublicKey]) -> int:
    info = getAccountData(client, sol_account, ACCOUNT_INFO_LAYOUT.sizeof())
    acc_info = AccountInfo.frombytes(info)
    res = int.from_bytes(acc_info.tx_count, 'little')
    print('getTransactionCount {}: {}'.format(sol_account, res))
    return res


def getNeonBalance(client: Client, sol_account: Union[str, PublicKey]) -> int:
    info = getAccountData(client, sol_account, ACCOUNT_INFO_LAYOUT.sizeof())
    account = ACCOUNT_INFO_LAYOUT.parse(info)
    balance = int.from_bytes(account.balance, byteorder="little")
    print('getNeonBalance {}: {}'.format(sol_account, balance))
    return balance


def wallet_path():
    res = solana_cli().call("config get")
    substr = "Keypair Path: "
    for line in res.splitlines():
        if line.startswith(substr):
            return line[len(substr):].strip()
    raise Exception("cannot get keypair path")


def operator1_keypair_path():
    res = solana_cli().call("config get")
    substr = "Keypair Path: "
    for line in res.splitlines():
        if line.startswith(substr):
            return line[len(substr):].strip()
    raise Exception("cannot get keypair path")


def operator2_keypair_path():
    return "/root/.config/solana/id2.json"


def send_transaction(client, trx, acc):
    result = client.send_transaction(trx, acc, opts=TxOpts(skip_confirmation=True, preflight_commitment="confirmed"))
    confirm_transaction(client, result["result"])
    result = client.get_confirmed_transaction(result["result"])
    return result


def create_neon_evm_instr_05_single(evm_loader_program_id,
                                    caller_sol_acc,
                                    operator_sol_acc,
                                    contract_sol_acc,
                                    code_sol_acc,
                                    collateral_pool_index_buf,
                                    collateral_pool_address,
                                    evm_instruction,
                                    add_meta=[]):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("05") + collateral_pool_index_buf + evm_instruction,
        keys=[
                 # System instructions account:
                 AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),

                 # Operator's SOL account:
                 AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
                 # Collateral pool address:
                 AccountMeta(pubkey=collateral_pool_address, is_signer=False, is_writable=True),
                 # Operator's NEON account:
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
                 # System program account:
                 AccountMeta(pubkey=PublicKey(system), is_signer=False, is_writable=False),
                 # NeonEVM program account
                 AccountMeta(pubkey=evm_loader_program_id, is_signer=False, is_writable=False),

                 AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),

             ] + add_meta + [
                 AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
             ])


def create_neon_evm_instr_13_partial_call_or_continue(evm_loader_program_id,
                                                      caller_sol_acc,
                                                      operator_sol_acc,
                                                      storage_sol_acc,
                                                      contract_sol_acc,
                                                      code_sol_acc,
                                                      collateral_pool_index_buf,
                                                      collateral_pool_address,
                                                      step_count,
                                                      evm_instruction,
                                                      writable_code=True,
                                                      add_meta=[]):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("0D") + collateral_pool_index_buf + step_count.to_bytes(8,
                                                                                       byteorder='little') + evm_instruction,
        keys=[
                 AccountMeta(pubkey=storage_sol_acc, is_signer=False, is_writable=True),
                 # System instructions account:
                 AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),

                 # Operator's SOL account:
                 AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
                 # Collateral pool address:
                 AccountMeta(pubkey=collateral_pool_address, is_signer=False, is_writable=True),
                 # Operator's NEON account:
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
                 # System program account:
                 AccountMeta(pubkey=PublicKey(system), is_signer=False, is_writable=False),
                 # NeonEVM program account
                 AccountMeta(pubkey=evm_loader_program_id, is_signer=False, is_writable=False),

                 AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=writable_code),
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),

                 AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),
             ] + add_meta + [
                 AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
             ])


def create_neon_evm_instr_19_partial_call(evm_loader_program_id,
                                          caller_sol_acc,
                                          operator_sol_acc,
                                          storage_sol_acc,
                                          contract_sol_acc,
                                          code_sol_acc,
                                          collateral_pool_index_buf,
                                          collateral_pool_address,
                                          step_count,
                                          evm_instruction,
                                          writable_code=True,
                                          add_meta=[]):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("13") + collateral_pool_index_buf + step_count.to_bytes(8,
                                                                                       byteorder='little') + evm_instruction,
        keys=[
                 AccountMeta(pubkey=storage_sol_acc, is_signer=False, is_writable=True),
                 # System instructions account:
                 AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),

                 # Operator's SOL account:
                 AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
                 # Collateral pool address:
                 AccountMeta(pubkey=collateral_pool_address, is_signer=False, is_writable=True),
                 # Operator's NEON account:
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
                 # System program account:
                 AccountMeta(pubkey=PublicKey(system), is_signer=False, is_writable=False),
                 # NeonEVM program account
                 AccountMeta(pubkey=evm_loader_program_id, is_signer=False, is_writable=False),

                 AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=writable_code),
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
             ] + add_meta + [
                 AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
             ])


def create_neon_evm_instr_20_continue(evm_loader_program_id,
                                      caller_sol_acc,
                                      operator_sol_acc,
                                      storage_sol_acc,
                                      contract_sol_acc,
                                      code_sol_acc,
                                      collateral_pool_index_buf,
                                      collateral_pool_address,
                                      step_count,
                                      writable_code=True,
                                      add_meta=[]):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("14") + collateral_pool_index_buf + step_count.to_bytes(8, byteorder='little'),
        keys=[
                 # Operator's storage account:
                 AccountMeta(pubkey=storage_sol_acc, is_signer=False, is_writable=True),
                 # Operator's SOL account:
                 AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
                 # Collateral pool address:
                 AccountMeta(pubkey=collateral_pool_address, is_signer=False, is_writable=True),
                 # Operator's NEON account:
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
                 # System program account:
                 AccountMeta(pubkey=PublicKey(system), is_signer=False, is_writable=False),
                 # NeonEVM program account
                 AccountMeta(pubkey=evm_loader_program_id, is_signer=False, is_writable=False),

                 AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
                 AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=writable_code),
                 AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
             ] + add_meta + [
                 AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
             ])


def create_neon_evm_instr_22_begin(evm_loader_program_id,
                                   caller_sol_acc,
                                   operator_sol_acc,
                                   storage_sol_acc,
                                   holder_sol_acc,
                                   contract_sol_acc,
                                   code_sol_acc,
                                   collateral_pool_index_buf,
                                   collateral_pool_address,
                                   step_count):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("16") + collateral_pool_index_buf + step_count.to_bytes(8, byteorder='little'),
        keys=[
            AccountMeta(pubkey=holder_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=storage_sol_acc, is_signer=False, is_writable=True),

            # Operator's SOL account:
            AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
            # Collateral pool address:
            AccountMeta(pubkey=collateral_pool_address, is_signer=False, is_writable=True),
            # Operator's NEON token account:
            AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
            # System program account:
            AccountMeta(pubkey=PublicKey(system), is_signer=False, is_writable=False),
            # NeonEVM program account
            AccountMeta(pubkey=evm_loader_program_id, is_signer=False, is_writable=False),

            AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),

            AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        ])


def create_neon_evm_instr_21_cancel(evm_loader_program_id,
                                    caller_sol_acc,
                                    operator_sol_acc,
                                    storage_sol_acc,
                                    contract_sol_acc,
                                    code_sol_acc,
                                    nonce):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("15") + nonce.to_bytes(8, 'little'),
        keys=[
            AccountMeta(pubkey=storage_sol_acc, is_signer=False, is_writable=True),

            # Operator's SOL account:
            AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
            # Incinerator
            AccountMeta(pubkey=PublicKey(incinerator), is_signer=False, is_writable=True),

            AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),

            AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        ])


def create_neon_evm_instr_14_combined_continue(evm_loader_program_id,
                                               caller_sol_acc,
                                               operator_sol_acc,
                                               storage_sol_acc,
                                               holder_sol_acc,
                                               contract_sol_acc,
                                               code_sol_acc,
                                               collateral_pool_index_buf,
                                               collateral_pool_address,
                                               step_count):
    return TransactionInstruction(
        program_id=evm_loader_program_id,
        data=bytearray.fromhex("0E") + collateral_pool_index_buf + step_count.to_bytes(8, byteorder='little'),
        keys=[
            AccountMeta(pubkey=holder_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=storage_sol_acc, is_signer=False, is_writable=True),

            # Operator's SOL account:
            AccountMeta(pubkey=operator_sol_acc, is_signer=True, is_writable=True),
            # Collateral pool address:
            AccountMeta(pubkey=collateral_pool_address, is_signer=False, is_writable=True),
            # Operator's NEON account:
            AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),
            # System program account:
            AccountMeta(pubkey=PublicKey(system), is_signer=False, is_writable=False),
            # NeonEVM program account
            AccountMeta(pubkey=evm_loader_program_id, is_signer=False, is_writable=False),

            AccountMeta(pubkey=contract_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=code_sol_acc, is_signer=False, is_writable=True),
            AccountMeta(pubkey=caller_sol_acc, is_signer=False, is_writable=True),

            AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        ])


def evm_step_cost():
    operator_expences = PAYMENT_TO_TREASURE + LAMPORTS_PER_SIGNATURE
    return math.floor(operator_expences / EVM_STEPS)


class ComputeBudget():
    @staticmethod
    def requestUnits(units, additional_fee):
        return TransactionInstruction(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("00") + units.to_bytes(4, "little") + additional_fee.to_bytes(4, "little")
        )

    @staticmethod
    def requestHeapFrame(heapFrame):
        return TransactionInstruction(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("01") + heapFrame.to_bytes(4, "little")
        )


def TransactionWithComputeBudget(units=DEFAULT_UNITS, additional_fee=DEFAULT_ADDITIONAL_FEE,
                                 heapFrame=DEFAULT_HEAP_FRAME, **args):
    trx = Transaction(**args)
    if units: trx.add(ComputeBudget.requestUnits(units, additional_fee))
    if heapFrame: trx.add(ComputeBudget.requestHeapFrame(heapFrame))
    return trx
