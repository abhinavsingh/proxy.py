import eth_utils
import logging
import struct

from sha3 import keccak_256
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_CLOCK_PUBKEY, SYSVAR_RENT_PUBKEY
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from spl.token.constants import ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID
from spl.token.instructions import transfer2, Transfer2Params
from typing import Tuple

from .address import accountWithSeed, ether2program, getTokenAddr, EthereumAddress
from .constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM, COLLATERALL_POOL_MAX
from .layouts import CREATE_ACCOUNT_LAYOUT
from ..environment import EVM_LOADER_ID, ETH_TOKEN_MINT_ID , COLLATERAL_POOL_BASE, NEW_USER_AIRDROP_AMOUNT


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


obligatory_accounts = [
    AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
]


def create_account_with_seed_layout(base, seed, lamports, space):
    return SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type = InstructionType.CREATE_ACCOUNT_WITH_SEED,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed), chars=seed),
                lamports=lamports,
                space=space,
                program_id=bytes(PublicKey(EVM_LOADER_ID))
            )
        )
    )


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


class NeonInstruction:
    def __init__(self, operator):
        self.operator_account = operator
        self.operator_neon_address = getTokenAddr(self.operator_account)


    def init_eth_trx(self, eth_trx, eth_accounts, caller_token):
        self.eth_accounts = eth_accounts
        self.caller_token = caller_token

        self.eth_trx = eth_trx

        self.msg = bytes.fromhex(self.eth_trx.sender()) + self.eth_trx.signature() + self.eth_trx.unsigned_msg()

        hash = keccak_256(self.eth_trx.unsigned_msg()).digest()
        collateral_pool_index = int().from_bytes(hash[:4], "little") % COLLATERALL_POOL_MAX
        self.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')
        self.collateral_pool_address = self.create_collateral_pool_address(collateral_pool_index)

        return self


    def init_iterative(self, storage, holder, perm_accs_id):
        self.storage = storage
        self.holder = holder
        self.perm_accs_id = perm_accs_id

        return self

    @staticmethod
    def create_collateral_pool_address(collateral_pool_index):
        COLLATERAL_SEED_PREFIX = "collateral_seed_"
        seed = COLLATERAL_SEED_PREFIX + str(collateral_pool_index)
        return accountWithSeed(PublicKey(COLLATERAL_POOL_BASE), str.encode(seed))


    def create_account_with_seed_trx(self, account, seed, lamports, space):
        seed_str = str(seed, 'utf8')
        logger.debug(f"createAccountWithSeedTrx {self.operator_account} account({account} seed({seed_str})")
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),
            ],
            program_id=SYS_PROGRAM_ID,
            data=create_account_with_seed_layout(self.operator_account, seed_str, lamports, space)
        )


    def make_create_eth_account_trx(self, eth_address: EthereumAddress, code_acc=None) -> Tuple[Transaction, PublicKey]:
        if isinstance(eth_address, str):
            eth_address = EthereumAddress(eth_address)
        pda_account, nonce = ether2program(eth_address)
        neon_token_account = getTokenAddr(PublicKey(pda_account))
        logger.debug(f'Create eth account: {eth_address}, sol account: {pda_account}, neon_token_account: {neon_token_account}, nonce: {nonce}')

        base = self.operator_account
        data = create_account_layout(0, 0, bytes(eth_address), nonce)
        trx = Transaction()
        if code_acc is None:
            trx.add(TransactionInstruction(
                program_id=EVM_LOADER_ID,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=PublicKey(pda_account), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=neon_token_account, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
                ]))
        else:
            trx.add(TransactionInstruction(
                program_id=EVM_LOADER_ID,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=PublicKey(pda_account), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=neon_token_account, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ETH_TOKEN_MINT_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
                ]))
        return trx, neon_token_account


    def createERC20TokenAccountTrx(self, token_info) -> Transaction:
        trx = Transaction()
        trx.add(TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["key"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["owner"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["contract"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(token_info["mint"]), is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        ))

        return trx


    def make_transfer_instruction(self, associated_token_account: PublicKey) -> TransactionInstruction:
        transfer_instruction = transfer2(Transfer2Params(
            source=self.operator_neon_address,
            owner=self.operator_account,
            dest=associated_token_account,
            amount=NEW_USER_AIRDROP_AMOUNT * eth_utils.denoms.gwei,
            decimals=9,
            mint=ETH_TOKEN_MINT_ID,
            program_id=TOKEN_PROGRAM_ID
        ))
        logger.debug(f"Token transfer from token: {self.operator_neon_address}, owned by: {self.operator_account}, to token: "
                    f"{associated_token_account}, owned by: {associated_token_account} , value: {NEW_USER_AIRDROP_AMOUNT}")
        return transfer_instruction


    def make_trx_with_create_and_airdrop(self, eth_account, code_acc=None) -> Transaction:
        trx = Transaction()
        create_trx, associated_token_account = self.make_create_eth_account_trx(eth_account, code_acc)
        trx.add(create_trx)
        if NEW_USER_AIRDROP_AMOUNT <= 0:
            return trx
        transfer_instruction = self.make_transfer_instruction(associated_token_account)
        trx.add(transfer_instruction)

        return trx


    def make_resize_instruction(self, account, code_account_old, code_account_new, seed) -> TransactionInstruction:
        return TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("11") + bytes(seed), # 17- ResizeStorageAccount
            keys = [
                AccountMeta(pubkey=PublicKey(account), is_signer=False, is_writable=True),
                (
                    AccountMeta(pubkey=code_account_old, is_signer=False, is_writable=True)
                    if code_account_old else
                    AccountMeta(pubkey=PublicKey("11111111111111111111111111111111"), is_signer=False, is_writable=False)
                ),
                AccountMeta(pubkey=code_account_new, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False)
            ],
        )


    def make_write_transaction(self, offset: int, data: bytes) -> Transaction:
        return Transaction().add(TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=write_holder_layout(self.perm_accs_id, offset, data),
            keys=[
                AccountMeta(pubkey=self.holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),
            ]
        ))


    def make_keccak_instruction(self, check_instruction_index, msg_len, data_start) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=KECCAK_PROGRAM,
            data=make_keccak_instruction_data(check_instruction_index, msg_len, data_start),
            keys=[
                AccountMeta(pubkey=KECCAK_PROGRAM, is_signer=False, is_writable=False),
            ]
        )


    def make_05_call_instruction(self) -> TransactionInstruction:
        return TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("05") + self.collateral_pool_index_buf + self.msg,
            keys = [
                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + obligatory_accounts
        )


    def make_noniterative_call_transaction(self, length_before: int = 0) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_trx.unsigned_msg()), 5))
        trx.add(self.make_05_call_instruction())
        return trx


    def make_cancel_transaction(self) -> Transaction:
        return Transaction().add(TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("15") + self.eth_trx.nonce.to_bytes(8, 'little'),
            keys = [
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
        ))


    def make_partial_call_or_continue_instruction(self, steps=0) -> TransactionInstruction:
        data = bytearray.fromhex("0D") + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder="little") + self.msg
        return TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = data,
            keys = [
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
        )


    def make_partial_call_or_continue_transaction(self, steps=0, length_before=0) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_trx.unsigned_msg()), 13))
        trx.add(self.make_partial_call_or_continue_instruction(steps))
        return trx


    def make_partial_call_or_continue_from_account_data(self, steps, index=0) -> Transaction:
        data = bytearray.fromhex("0E") + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder='little')
        if index:
            data = data + index.to_bytes(8, byteorder="little")
        return Transaction().add(TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = data,
            keys = [
                AccountMeta(pubkey=self.holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),

            ] + self.eth_accounts + [

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
            ] + obligatory_accounts
        ))
