import struct

from sha3 import keccak_256
from solana._layouts.system_instructions import SYSTEM_INSTRUCTIONS_LAYOUT, InstructionType
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
from spl.token.constants import TOKEN_PROGRAM_ID
from logged_groups import logged_group

from ..common_neon.elf_params import ElfParams

from .address import accountWithSeed, ether2program, EthereumAddress
from .constants import SYSVAR_INSTRUCTION_PUBKEY, INCINERATOR_PUBKEY, KECCAK_PROGRAM, COLLATERALL_POOL_MAX
from .layouts import CREATE_ACCOUNT_LAYOUT
from .environment_data import EVM_LOADER_ID

obligatory_accounts = [
    AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
]


def create_account_with_seed_layout(base, seed, lamports, space):
    return SYSTEM_INSTRUCTIONS_LAYOUT.build(
        dict(
            instruction_type=InstructionType.CREATE_ACCOUNT_WITH_SEED,
            args=dict(
                base=bytes(base),
                seed=dict(length=len(seed), chars=seed),
                lamports=lamports,
                space=space,
                program_id=bytes(PublicKey(EVM_LOADER_ID))
            )
        )
    )


def create_account_layout(ether, nonce):
    return bytes.fromhex("18")+CREATE_ACCOUNT_LAYOUT.build(dict(
        ether=ether,
        nonce=nonce
    ))


def write_holder_layout(nonce, offset, data):
    return (bytes.fromhex('12') +
            nonce.to_bytes(8, byteorder='little') +
            offset.to_bytes(4, byteorder='little') +
            len(data).to_bytes(8, byteorder='little') +
            data)


def make_keccak_instruction_data(check_instruction_index, msg_len, data_start):
    if check_instruction_index > 255 or check_instruction_index < 0:
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


@logged_group("neon.Proxy")
class NeonInstruction:
    def __init__(self, operator: PublicKey):
        self.operator_account = operator
        self.operator_neon_address = None
        self.eth_accounts = []
        self.eth_trx = None
        self.msg = None
        self.collateral_pool_index_buf = None
        self.collateral_pool_address = None
        self.storage = None
        self.holder = None
        self.perm_accs_id = None

    def init_operator_ether(self, operator_ether: EthereumAddress):
        self.operator_neon_address = ether2program(operator_ether)[0]

    def init_eth_trx(self, eth_trx, eth_accounts):
        self.eth_accounts = eth_accounts

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
        collateral_pool_base = PublicKey(ElfParams().collateral_pool_base)
        return accountWithSeed(collateral_pool_base, str.encode(seed))

    def create_account_with_seed_instruction(self, account, seed, lamports, space) -> TransactionInstruction:
        seed_str = str(seed, 'utf8')
        self.debug(f"createAccountWithSeedTrx {self.operator_account} account({account} seed({seed_str})")
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),
            ],
            program_id=SYS_PROGRAM_ID,
            data=create_account_with_seed_layout(self.operator_account, seed_str, lamports, space)
        )

    def make_create_eth_account_instruction(self, eth_address: EthereumAddress, code_acc=None) -> TransactionInstruction:
        if isinstance(eth_address, str):
            eth_address = EthereumAddress(eth_address)
        pda_account, nonce = ether2program(eth_address)
        self.debug(f'Create eth account: {eth_address}, sol account: {pda_account}, nonce: {nonce}')

        base = self.operator_account
        data = create_account_layout(bytes(eth_address), nonce)
        if code_acc is None:
            return TransactionInstruction(
                program_id=EVM_LOADER_ID,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=PublicKey(pda_account), is_signer=False, is_writable=True),
                ])
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=PublicKey(pda_account), is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
            ])

    def make_erc20token_account_instruction(self, token_info) -> TransactionInstruction:
        return TransactionInstruction(
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
        )

    def make_resize_instruction(self, account, code_account_old, code_account_new, seed) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytearray.fromhex("11") + bytes(seed),  # 17- ResizeStorageAccount
            keys=[
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

    def make_write_instruction(self, offset: int, data: bytes) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=write_holder_layout(self.perm_accs_id, offset, data),
            keys=[
                AccountMeta(pubkey=self.holder, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),
            ]
        )

    @staticmethod
    def make_keccak_instruction(check_instruction_index, msg_len, data_start) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=KECCAK_PROGRAM,
            data=make_keccak_instruction_data(check_instruction_index, msg_len, data_start),
            keys=[
                AccountMeta(pubkey=KECCAK_PROGRAM, is_signer=False, is_writable=False),
            ]
        )

    def make_05_call_instruction(self) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=bytearray.fromhex("05") + self.collateral_pool_index_buf + self.msg,
            keys=[
                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
            ] + self.eth_accounts + obligatory_accounts
        )

    def make_noniterative_call_transaction(self, length_before: int) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_trx.unsigned_msg()), 5))
        trx.add(self.make_05_call_instruction())
        return trx

    def make_cancel_instruction(self, storage=None, nonce=None, cancel_keys=None) -> TransactionInstruction:
        if cancel_keys:
            append_keys = cancel_keys
        else:
            append_keys = self.eth_accounts
            append_keys += obligatory_accounts
        if nonce is None:
            nonce = self.eth_trx.nonce
        if storage is None:
            storage = self.storage
        return TransactionInstruction(
            program_id = EVM_LOADER_ID,
            data = bytearray.fromhex("15") + nonce.to_bytes(8, 'little'),
            keys=[
                AccountMeta(pubkey=storage, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
            ] + append_keys
        )

    def make_partial_call_or_continue_instruction(self, steps: int) -> TransactionInstruction:
        data = bytearray.fromhex("0D") + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder="little") + self.msg
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
            ] + self.eth_accounts + obligatory_accounts
        )

    def make_partial_call_or_continue_transaction(self, steps: int, length_before: int) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_trx.unsigned_msg()), 13))
        trx.add(self.make_partial_call_or_continue_instruction(steps))
        return trx

    def _make_partial_call_or_continue_from_account_data(self,
                                                         ix_id: str,
                                                         steps: int,
                                                         index: int) -> TransactionInstruction:
        data = bytearray.fromhex(ix_id) + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder='little')
        if index:
            data = data + index.to_bytes(8, byteorder="little")
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=data,
            keys=[
                     AccountMeta(pubkey=self.holder, is_signer=False, is_writable=True),
                     AccountMeta(pubkey=self.storage, is_signer=False, is_writable=True),

                     AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                     AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                     AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                     AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                     AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
                 ] + self.eth_accounts + obligatory_accounts
        )

    def make_partial_call_or_continue_from_account_data_instruction(self,
                                                                    steps: int,
                                                                    index: int) -> TransactionInstruction:
        return self._make_partial_call_or_continue_from_account_data('0E', steps, index)

    def make_partial_call_or_continue_from_account_data_no_chainid_instruction(self,
                                                                               steps: int,
                                                                               index: int) -> TransactionInstruction:
        return self._make_partial_call_or_continue_from_account_data('1B', steps, index)
