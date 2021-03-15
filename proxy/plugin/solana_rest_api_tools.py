from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from solana.sysvar import *
from solana.blockhash import Blockhash
import time
import subprocess
import os
import base64
from eth_keys import keys as eth_keys
from typing import NamedTuple
import random
import json
from sha3 import keccak_256
import struct
from .eth_proto import pack, unpack
from solana.rpc.types import TxOpts

from construct import Bytes, Int8ul, Int32ul, Int64ul, Struct as cStruct
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType as SystemInstructionType
from hashlib import sha256
from eth_keys import keys
from web3.auto import w3



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

def createAccountWithSeed(funding, base, seed, lamports, space, program):
    data = SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type = SystemInstructionType.CreateAccountWithSeed,
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
    created = PublicKey(sha256(bytes(base)+bytes(seed, 'utf8')+bytes(program)).digest())
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



def getInt(a):
    if isinstance(a, int): return a
    if isinstance(a, bytes): return int.from_bytes(a, 'big')
    if a == None: return a
    raise Exception("Invalid convertion from {} to int".format(a))


class Trx:
    def __init__(self):
        self.nonce = None
        self.gasPrice = None
        self.gasLimit = None
        self.toAddress = None
        self.value = None
        self.callData = None
        self.v = None
        self.r = None
        self.s = None

    @classmethod
    def fromString(cls, s):
        t = Trx()
        (unpacked, data) = unpack(memoryview(s))
        (nonce, gasPrice, gasLimit, toAddress, value, callData, v, r, s) = unpacked
        t.nonce = getInt(nonce)
        t.gasPrice = getInt(gasPrice)
        t.gasLimit = getInt(gasLimit)
        t.toAddress = toAddress
        t.value = getInt(value)
        t.callData = callData
        t.v = getInt(v)
        t.r = getInt(r)
        t.s = getInt(s)
        return t

    def chainId(self):
        # chainid*2 + 35  xxxxx0 + 100011   xxxx0 + 100010 +1
        # chainid*2 + 36  xxxxx0 + 100100   xxxx0 + 100011 +1
        return (self.v - 1) // 2 - 17

    def __str__(self):
        return pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            self.v,
            self.r.to_bytes(32, 'big') if self.r else None,
            self.s.to_bytes(32, 'big') if self.s else None)
        ).hex()

    def get_msg(self, chainId=None):
        return pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            chainId or self.chainId(), None, None))

    def hash(self, chainId=None):
        trx = pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            chainId or self.chainId(), None, None))
        return keccak_256(trx).digest()

    def sender(self):
        msgHash = self.hash()
        sig = eth_keys.Signature(vrs=[1 if self.v % 2 == 0 else 0, self.r, self.s])
        pub = sig.recover_public_key_from_msg_hash(msgHash)
        return pub.to_canonical_address().hex()

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
    cmd = 'emulator  {} {} {} {} {}'.format(solana_url, evm_loader_id, contract, sender, data)
    try:
        return subprocess.check_output(cmd, shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as err:
        import sys
        print("ERR: solana error {}".format(err))
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
            print("ERR: solana error {}".format(err))
            raise

def confirm_transaction(client, tx_sig):
    """Confirm a transaction."""
    TIMEOUT = 30  # 30 seconds  pylint: disable=invalid-name
    elapsed_time = 0
    while elapsed_time < TIMEOUT:
        resp = client.get_confirmed_transaction(tx_sig)
        if resp["result"]:
#            print('Confirmed transaction:', resp)
            break
        sleep_time = 3
        if not elapsed_time:
            sleep_time = 7
            time.sleep(sleep_time)
        else:
            time.sleep(sleep_time)
        elapsed_time += sleep_time
    if not resp["result"]:
        raise RuntimeError("could not confirm transaction: ", tx_sig)
    return resp

def solana2ether(public_key):
    from web3 import Web3
    return bytes(Web3.keccak(bytes.fromhex(public_key))[-20:])

def create_program_address(seed, program_id):
    cli = solana_cli(solana_url)
    output = cli.call("create-program-address {} {}".format(seed, program_id))
    items = output.rstrip().split('  ')
    return (items[0], int(items[1]))


def call(input, evm_loader, program, acc, client):
    trx = Transaction().add(
        TransactionInstruction(program_id=evm_loader, data=input, keys=
        [
            AccountMeta(pubkey=program, is_signer=False, is_writable=True),
            AccountMeta(pubkey=acc.public_key(), is_signer=False, is_writable=True),
            AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
            AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
            AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
        ]))

    try:
        # TODO: Cache recent blockhash
        blockhash_resp = client.get_recent_blockhash()
        if not blockhash_resp["result"]:
            raise RuntimeError("failed to get recent blockhash")
        trx.recent_blockhash = Blockhash(blockhash_resp["result"]["value"]["blockhash"])
    except Exception as err:
        raise RuntimeError("failed to get recent blockhash") from err

    trx.sign(acc)
    result = client.simulate_transaction(trx)
    messages = result['result']['value']['logs']
    res = messages[messages.index("Program log: succeed") + 1]
    print("CALL:", res)
    if not res.startswith("Program log: "):
        raise Exception("Invalid program logs: no result")
    else:
        return res[13:]

def call_signed(acc, client, trx_raw):

    trx_parsed = Trx.fromString(bytes.fromhex(trx_raw[2:]))
    sender_ether = bytes.fromhex(trx_parsed.sender())
    (contract_sol, _) = create_program_address(trx_parsed.toAddress.hex(), evm_loader_id)
    (sender_sol, _) = create_program_address(sender_ether.hex(), evm_loader_id)

    sender_sol_info = client.get_account_info(sender_sol)
    if sender_sol_info['result']['value'] is None:
        print("Create solana caller account...")
        cli = solana_cli(solana_url)
        output = cli.call("create-ether-account {} {} 10".format(evm_loader_id, sender_ether.hex()))
        result = json.loads(output.splitlines()[-1])
        sender_sol = result["solana"]
        print("Done")

    print("solana caller:", sender_sol)

    trx_rlp = trx_parsed.get_msg()
    eth_sig = eth_keys.Signature(vrs=[1 if trx_parsed.v % 2 == 0 else 0, trx_parsed.r, trx_parsed.s]).to_bytes()
    keccak_instruction = make_keccak_instruction_data(1, len(trx_rlp))
    evm_instruction = sender_ether + eth_sig + trx_rlp

    output_em = emulator(trx_parsed.toAddress.hex(), sender_ether.hex(), trx_parsed.callData.hex())
    output_json = json.loads(output_em.splitlines()[-1])
    add_keys_05 = []
    if output_json["exit_status"] == 'succeed':
        for acc_desc in output_json["accounts"]:
            if acc_desc["new"] == True:
                call_inner_eth = acc_desc['address'][2:]
                (call_inner, _) = create_program_address(call_inner_eth, evm_loader_id)
                call_inner_info = client.get_account_info(call_inner)
                if call_inner_info['result']['value'] is None:
                    print("Create solana call_inner account...")
                    cli = solana_cli(solana_url)
                    output = cli.call("create-ether-account {} {} 10".format(evm_loader_id, call_inner_eth))
                    result = json.loads(output.splitlines()[-1])
                    call_inner = result["solana"]
                    print("Done call_inner:", call_inner)
                add_keys_05.append( AccountMeta(pubkey=call_inner, is_signer=False, is_writable=False))

    print("transaction:", evm_instruction.hex())

    trx = Transaction().add(
        TransactionInstruction(program_id=keccakprog, data=keccak_instruction, keys=[
            AccountMeta(pubkey=PublicKey(keccakprog), is_signer=False, is_writable=False), ])).add(
        TransactionInstruction(program_id=evm_loader_id,
                               data=bytearray.fromhex("05") + evm_instruction,
                               keys=[
                                   AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
                                   AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
                                   AccountMeta(pubkey=PublicKey(sysinstruct), is_signer=False, is_writable=False),
                                   AccountMeta(pubkey=evm_loader_id, is_signer=False, is_writable=False),
                                   AccountMeta(pubkey=PublicKey(sysvarclock), is_signer=False, is_writable=False),
                               ] + add_keys_05))

    result = client.send_transaction(trx, acc)
    result = confirm_transaction(client, result["result"])
    messages = result["result"]["meta"]["logMessages"]
    return (messages[messages.index("Program log: succeed") + 1], result)

def deploy(contract, evm_loader):
    with open(location_bin, mode='wb') as file:
        file.write(contract)

    cli = solana_cli(solana_url)
    output = cli.call("deploy --use-evm-loader {} {}".format(evm_loader, location_bin))
    print(type(output), output)
    return json.loads(output.splitlines()[-1])

def deploy_contract(acc, client, sender_eth, content):
    (sender_sol, _) = create_program_address(sender_eth, evm_loader_id)
    print("Sender account solana:", sender_sol)

    sender_sol_info = client.get_account_info(sender_sol)
    if sender_sol_info['result']['value'] is None:
        print("Create sender solana account...")
        cli = solana_cli(solana_url)
        output = cli.call("create-ether-account {} {} 10".format(evm_loader_id, sender_eth))
        result = json.loads(output.splitlines()[-1])
        sender_sol = result["solana"]
        print("Done")


    info = _getAccountData(client, sender_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    trx_count = int.from_bytes(AccountInfo.frombytes(info).trx_count, 'little')
    print("Sender solana trx_count:", trx_count)

    # Create legacy contract address from (sender_eth, nonce)
    rlp = pack((bytes().fromhex(sender_eth) , trx_count or None))
    contract_eth = keccak_256(rlp).digest()[-20:]
    (contract_sol, contract_nonce) = create_program_address(contract_eth.hex(), evm_loader_id)

    print("Legacy contract address ether:", contract_eth.hex())
    print("Legacy contract address solana:", contract_sol, contract_nonce)

    # Create transaction holder account (if not exists)
    seed = "1236"
    holder = PublicKey(
        sha256(bytes(acc.public_key()) + bytes(seed, 'utf8') + bytes(PublicKey(evm_loader_id))).digest())
    print("Holder", holder)

    if client.get_balance(holder)['result']['value'] == 0:
        trx = Transaction()
        trx.add(createAccountWithSeed(acc.public_key(), acc.public_key(), "1236", 10 ** 9, 128 * 1024,
                                      PublicKey(evm_loader_id)))
        result = client.send_transaction(trx, acc, opts=TxOpts(skip_confirmation=False))
        print(result)


    # Build deploy transaction
    tx = {
        'to': None,
        'value': 0,
        'gas': 1,
        'gasPrice': 1,
        'nonce': trx_count,
        'data': content,
        'chainId': 1
    }
    (from_addr, sign, msg) = make_instruction_data_from_tx(tx, acc.secret_key())
    msg = len(msg).to_bytes(8, byteorder="little") + msg
    # print("msg", msg.hex())

    # Write transaction to transaction holder account
    offset = 0
    receipts = []
    rest = msg
    while len(rest):
        (part, rest) = (rest[:1000], rest[1000:])
        trx = Transaction()
        print("sender_sol", sender_sol, holder, acc.public_key())
        trx.add(TransactionInstruction(program_id=evm_loader_id,
                                       data=write_layout(offset, part),
                                       keys=[
                                           AccountMeta(pubkey=holder, is_signer=False, is_writable=True),
                                           AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=False),
                                       ]))
        receipts.append(client.send_transaction(trx, acc)["result"])
        offset += len(part)
    print("receipts", receipts)
    for rcpt in receipts:
        confirm_transaction(client, rcpt)
        print("confirmed:", rcpt)

    # Create contract account & execute deploy transaction
    print("    # Create contract account ")
    trx = Transaction()
    trx.add(TransactionInstruction(program_id=evm_loader_id,
                                   data=create_account_layout(10 ** 9, len(msg) + 2048, contract_eth, contract_nonce),
                                   keys=[
                                       AccountMeta(pubkey=acc.public_key(), is_signer=True, is_writable=True),
                                       AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
                                       AccountMeta(pubkey=system, is_signer=False, is_writable=False),
                                   ]))
    print("    #  execute deploy transaction")
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
                                          opts=TxOpts(skip_confirmation=False, preflight_commitment="root"))

    signature = result["result"]["transaction"]["signatures"][0]
    return (signature, '0x'+contract_eth.hex())

def transaction_history(acc):
    cli = solana_cli(solana_url)
    output = cli.call("transaction-history {}".format(acc))
    return output.splitlines()[-2]

def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) != expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data

def getAccountInfo(client, eth_acc):
    (account_sol, nonce) = create_program_address(bytes(eth_acc).hex(), evm_loader_id)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)

def getLamports(client, evm_loader, eth_acc):
    (account, nonce) = create_program_address(bytes(eth_acc).hex(), evm_loader)
    return int(client.get_balance(account)['result']['value'])


def make_instruction_data_from_tx(instruction, private_key=None):
    if isinstance(instruction, dict):
        if instruction['chainId'] == None:
            raise Exception("chainId value is needed in input dict")
        if private_key == None:
            raise Exception("Needed private key for transaction creation from fields")

        signed_tx = w3.eth.account.sign_transaction(instruction, private_key)
        # print(signed_tx.rawTransaction.hex())
        _trx = Trx.fromString(signed_tx.rawTransaction)
        # print(json.dumps(_trx.__dict__, cls=JsonEncoder, indent=3))

        raw_msg = _trx.get_msg(instruction['chainId'])
        sig = keys.Signature(vrs=[1 if _trx.v % 2 == 0 else 0, _trx.r, _trx.s])
        pub = sig.recover_public_key_from_msg_hash(_trx.hash())

        # print(pub.to_hex())

        return (pub.to_canonical_address(), sig.to_bytes(), raw_msg)
    elif isinstance(instruction, str):
        if instruction[:2] == "0x":
            instruction = instruction[2:]

        _trx = Trx.fromString(bytearray.fromhex(instruction))
        # print(json.dumps(_trx.__dict__, cls=JsonEncoder, indent=3))

        raw_msg = _trx.get_msg()
        sig = keys.Signature(vrs=[1 if _trx.v % 2 == 0 else 0, _trx.r, _trx.s])
        pub = sig.recover_public_key_from_msg_hash(_trx.hash())

        data = pub.to_canonical_address()
        data += sig.to_bytes()
        data += raw_msg

        return (pub.to_canonical_address(), sig.to_bytes(), raw_msg)
    else:
        raise Exception("function gets ")
