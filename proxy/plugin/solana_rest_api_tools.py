from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from solana.sysvar import *
from solana.blockhash import Blockhash
import time
import subprocess
import os
import base64
from base58 import b58encode
from eth_keys import keys as eth_keys
from typing import NamedTuple
import random
import json
from sha3 import keccak_256
import struct
import rlp
from .eth_proto import Trx
from solana.rpc.types import TxOpts

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
#evm_loader_id = "9TdKEctsU5L7mfMTrdBrsxHnxGbTgMiUbtSoJrEZYecs"
location_bin = ".deploy_contract.bin"

tokenkeg = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
sysvarclock = "SysvarC1ock11111111111111111111111111111111"
sysinstruct = "Sysvar1nstructions1111111111111111111111111"
keccakprog = "KeccakSecp256k11111111111111111111111111111"
rentid = "SysvarRent111111111111111111111111111111111"
system = "11111111111111111111111111111111"

ACCOUNT_INFO_LAYOUT = cStruct(
    "eth_acc" / Bytes(20),
    "nonce" / Int8ul,
    "trx_count" / Bytes(8),
    "signer_acc" / Bytes(32),
    "code_size" / Int32ul
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





def make_keccak_instruction_data(check_instruction_index, msg_len):
    if check_instruction_index > 255 and check_instruction_index < 0:
        raise Exception("Invalid index for instruction - {}".format(check_instruction_index))

    check_count = 1
    data_start = 1
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


def emulator(base_account, contract, sender, data):
    cmd = 'emulator {} {} {} {} {} {}'.format(solana_url, base_account, evm_loader_id, contract, sender, data)
    try:
        return subprocess.check_output(cmd, shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as err:
        import sys
        logger.debug("ERR: solana error {}".format(err))
        raise


class solana_cli:
    def __init__(self, url):
        self.url = url

    def call(self, arguments):
        cmd = 'solana --url {} {}'.format(self.url, arguments)
        try:
            return subprocess.check_output(cmd, shell=True, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            logger.debug("ERR: solana error {}".format(err))
            raise

def finalize_transaction(client, tx_sig):
    """Confirm a transaction."""
    TIMEOUT = 30  # 30 seconds  pylint: disable=invalid-name
    elapsed_time = 0
    while elapsed_time < TIMEOUT:
        resp = client.get_confirmed_transaction(tx_sig)
        if resp["result"]:
#            logger.debug('Confirmed transaction:', resp)
            break
        sleep_time = 3
        if not elapsed_time:
            sleep_time = 7
            time.sleep(sleep_time)
        else:
            time.sleep(sleep_time)
        elapsed_time += sleep_time
    if not resp["result"]:
        raise RuntimeError("could not finalize transaction: ", tx_sig)
    return resp

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

def create_program_address(ether, program_id, base):
#    cli = solana_cli(solana_url)
#    output = cli.call("create-program-address {} {}".format(seed, program_id))
#    items = output.rstrip().split('  ')
#    return (items[0], int(items[1]))
    if isinstance(ether, str):
        if ether.startswith('0x'): ether = ether[2:]
    else: ether = ether.hex()
    seed = b58encode(bytes.fromhex(ether))
    acc = accountWithSeed(base, seed, PublicKey(program_id))
    logger.debug('ether2program: {} {} => {} (seed {})'.format(ether, 255, acc, seed))
    return (acc, 255)

def call_emulated(base_account, contract_id, caller_id, data):
    output = emulator(base_account.public_key(), contract_id, caller_id, data)
    result = json.loads(output)
    logger.debug("call_emulated %s %s %s return %s", contract_id, caller_id, data, result)
    exit_status = result['exit_status']
    if exit_status == 'revert':
        offset = int(result['result'][8:8+64], 16)
        length = int(result['result'][8+64:8+64+64], 16)
        message = str(bytes.fromhex(result['result'][8+offset*2+64:8+offset*2+64+length*2]), 'utf8')
        raise EthereumError(code=3, message='execution reverted: '+message, data='0x'+result['result'])
    if result["exit_status"] != "succeed":
        raise Exception("evm emulator error ", result)
    return result

def call_signed(acc, client, ethTrx):
    sender_ether = bytes.fromhex(ethTrx.sender())
    (contract_sol, _) = create_program_address(ethTrx.toAddress.hex(), evm_loader_id, acc.public_key())
    (sender_sol, _) = create_program_address(sender_ether.hex(), evm_loader_id, acc.public_key())

    trx = Transaction()
    sender_sol_info = client.get_account_info(sender_sol, commitment='recent')
    if sender_sol_info['result']['value'] is None:
        logger.debug("Create solana caller account...")
        trx.add(createEtherAccountTrx(client, sender_ether, evm_loader_id, acc)[0])

    logger.debug("solana caller: %s", sender_sol)

    add_keys_05 = []
    output_json = call_emulated(acc, ethTrx.toAddress.hex(), sender_ether.hex(), ethTrx.callData.hex())
    logger.debug("emulator returns: %s", json.dumps(output_json, indent=3))
    for acc_desc in output_json["accounts"]:
        call_inner_eth = bytes.fromhex(acc_desc['address'][2:])
        (call_inner, _) = create_program_address(call_inner_eth, evm_loader_id, acc.public_key())
        if call_inner not in [contract_sol, sender_sol]:
            add_keys_05.append(AccountMeta(pubkey=call_inner, is_signer=False, is_writable=acc_desc["writable"]))
            if acc_desc["new"] == True:    
                logger.debug("Create solana account %s %s", call_inner_eth, call_inner)
                trx.add(createEtherAccountTrx(client, call_inner_eth, evm_loader_id, acc, space=20*1024)[0])

    trx.add(TransactionInstruction(
        program_id=keccakprog,
        data=make_keccak_instruction_data(len(trx.instructions)+1, len(ethTrx.unsigned_msg())),
        keys=[
            AccountMeta(pubkey=PublicKey(sender_sol), is_signer=False, is_writable=False),
        ]))
    trx.add(TransactionInstruction(
        program_id=evm_loader_id,
        data=bytearray.fromhex("05") + sender_ether + ethTrx.signature() + ethTrx.unsigned_msg(),
        keys=[
            AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
            AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),
            AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
        ] + add_keys_05 + [
            AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
        ]))

    result = client.send_transaction(trx, acc,
            opts=TxOpts(skip_confirmation=True, preflight_commitment="recent"))
    confirm_transaction(client, result['result'])
    return result["result"] #["transaction"]["signatures"][0]

def deploy(contract, evm_loader):
    with open(location_bin, mode='wb') as file:
        file.write(contract)

    cli = solana_cli(solana_url)
    output = cli.call("deploy --use-evm-loader {} {}".format(evm_loader, location_bin))
    #logger.debug(type(output), output)
    return json.loads(output.splitlines()[-1])

def createEtherAccountTrx(client, ether, evm_loader_id, signer, space=0):
    if isinstance(ether, str):
        if ether.startswith('0x'): ether = ether[2:]
    else: ether = ether.hex()
    (sol, nonce) = create_program_address(ether, evm_loader_id, signer.public_key())
    logger.debug('createEtherAccount: {} {} => {}'.format(ether, nonce, sol))
    seed = b58encode(bytes.fromhex(ether))
    base = signer.public_key()
    trx = Transaction()
    trx.add(createAccountWithSeed(base, base, seed, 10**9, 65+space, PublicKey(evm_loader_id)))
    trx.add(TransactionInstruction(
        program_id=evm_loader_id,
        data=bytes.fromhex('66000000')+CREATE_ACCOUNT_LAYOUT.build(dict(
            lamports=10**9,
            space=space,
            ether=bytes.fromhex(ether),
            nonce=nonce)),
        keys=[
            AccountMeta(pubkey=base, is_signer=True, is_writable=True),
            AccountMeta(pubkey=PublicKey(sol), is_signer=False, is_writable=True),
        ]))
    return (trx, sol)

def createEtherAccount(client, ether, evm_loader_id, signer, space=0):
    (trx, sol) = createEtherAccountTrx(client, ether, evm_loader_id, signer, space)
    result = client.send_transaction(trx, signer,
            opts=TxOpts(skip_confirmation=False, preflight_commitment="recent"))
    logger.debug('createEtherAccount result: %s', result)
    return sol

def deploy_contract(acc, client, ethTrx): 

    sender_ether = bytes.fromhex(ethTrx.sender())
    (sender_sol, _) = create_program_address(sender_ether.hex(), evm_loader_id, acc.public_key())
    logger.debug("Sender account solana: %s %s", sender_ether, sender_sol)

    #info = _getAccountData(client, sender_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    #trx_count = int.from_bytes(AccountInfo.frombytes(info).trx_count, 'little')
    #logger.debug("Sender solana trx_count: %s", trx_count)

    # Create legacy contract address from (sender_eth, nonce)
    #rlp = pack(sender_ether, ethTrx.nonce or None)
    contract_eth = keccak_256(rlp.encode((sender_ether, ethTrx.nonce))).digest()[-20:]
    (contract_sol, contract_nonce) = create_program_address(contract_eth.hex(), evm_loader_id, acc.public_key())

    logger.debug("Legacy contract address ether: %s", contract_eth.hex())
    logger.debug("Legacy contract address solana: %s %s", contract_sol, contract_nonce)

    # Create transaction holder account (if not exists)
    seed = bytes("1236", 'utf8')
    holder = PublicKey(
        sha256(bytes(acc.public_key()) + seed + bytes(PublicKey(evm_loader_id))).digest())
    logger.debug("Holder %s", holder)

    if client.get_balance(holder, commitment='recent')['result']['value'] == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), seed, 10 ** 9, 128 * 1024,
                                      PublicKey(evm_loader_id)))
        receipt = client.send_transaction(trx, acc, 
                opts=TxOpts(skip_confirmation=True, preflight_commitment="recent"))['result']
        confirm_transaction(client, receipt)

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
        logger.debug("sender_sol %s %s %s", sender_sol, holder, acc.public_key())
        trx.add(TransactionInstruction(program_id=evm_loader_id,
                                       data=write_layout(offset, part),
                                       keys=[
                                           AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                                           AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
                                       ]))
        receipts.append(client.send_transaction(trx, acc,
                opts=TxOpts(skip_confirmation=True, preflight_commitment="recent"))["result"])
        offset += len(part)
    logger.debug("receipts %s", receipts)
    for rcpt in receipts:
        confirm_transaction(client, rcpt)
        logger.debug("confirmed: %s", rcpt)

    # Create contract account & execute deploy transaction
    logger.debug("    # Create contract account & execute deploy transaction")
    trx = Transaction()
    sender_sol_info = client.get_account_info(sender_sol, commitment='recent')
    if sender_sol_info['result']['value'] is None:
        trx.add(createEtherAccountTrx(client, sender_ether, evm_loader_id, acc)[0])

    trx.add(createEtherAccountTrx(client, contract_eth, evm_loader_id, acc, space=65+len(msg)+2048)[0])
    trx.add(TransactionInstruction(program_id=evm_loader_id,
                                   data=bytes.fromhex('08'),
                                   keys=[
                                       AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                                       AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
                                       AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
                                       AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
                                       AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
                                   ]))
    result = client.send_transaction(trx, acc,
            opts=TxOpts(skip_confirmation=True, preflight_commitment="recent"))

    signature = result["result"] #["transaction"]["signatures"][0]
    confirm_transaction(client, signature)
    return (signature, '0x'+contract_eth.hex())

def transaction_history(acc):
    cli = solana_cli(solana_url)
    output = cli.call("transaction-history {}".format(acc))
    return output.splitlines()[-2]

def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account, commitment="recent")['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) != expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data

def getAccountInfo(client, eth_acc, base_account):
    (account_sol, nonce) = create_program_address(bytes(eth_acc).hex(), evm_loader_id, base_account)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)

def getLamports(client, evm_loader, eth_acc, base_account):
    (account, nonce) = create_program_address(bytes(eth_acc).hex(), evm_loader, base_account)
    return int(client.get_balance(account, commitment="recent")['result']['value'])


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
