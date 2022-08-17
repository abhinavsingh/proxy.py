import struct

from enum import Enum
from typing import Optional, List

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
from .eth_proto import Trx as EthTx
from .environment_data import EVM_LOADER_ID
from .utils import get_holder_msg
from ..common_neon.solana_alt import ADDRESS_LOOKUP_TABLE_ID


class EvmInstruction(Enum):
    CreateAccount = b'\x02' # 2 deprecated
    CallFromRawEthereumTX = b'\x05' # 5
    OnReturn = b'\x06' # 6 deprecated
    OnEvent = b'\x07' # 7 deprecated
    PartialCallFromRawEthereumTX = b'\x09' # 9 deprecated
    Continue = b'\x0a' # 10 deprecated
    ExecuteTrxFromAccountDataIterative = b'\x0b' # 11 deprecated
    Cancel = b'\x0c' # 12 deprecated
    PartialCallOrContinueFromRawEthereumTX = b'\x0d' # 13
    ExecuteTrxFromAccountDataIterativeOrContinue = b'\x0e' # 14
    ERC20CreateTokenAccount = b'\x0f' # 15
    DeleteHolderOrStorageAccount = b'\x10' # 16
    ResizeContractAccount = b'\x11' # 17
    WriteHolder = b'\x12' # 18
    PartialCallFromRawEthereumTXv02 = b'\x13' # 19
    ContinueV02 = b'\x14' # 20
    CancelWithNonce = b'\x15' # 21
    ExecuteTrxFromAccountDataIterativeV02 = b'\x16' # 22
    UpdateValidsTable = b'\x17' # 23
    CreateAccountV02 = b'\x18' # 24
    Deposit = b'\x19' # 25
    MigrateAccount = b'\x1a' # 26
    ExecuteTrxFromAccountDataIterativeOrContinueNoChainId = b'\x1b' # 27
    WriteValueToDistributedStorage = b'\x1c' # 28
    ConvertDataAccountFromV1ToV2 = b'\x1d' # 29
    CollectTreasure = b'\x1e' # 30


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
    return (EvmInstruction.CreateAccountV02.value +
            CREATE_ACCOUNT_LAYOUT.build(dict(
                ether=ether,
                nonce=nonce
            )))


def write_holder_layout(nonce, offset, data):
    return (EvmInstruction.WriteHolder.value +
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
class NeonIxBuilder:
    def __init__(self, operator: PublicKey):
        self.operator_account = operator
        self.operator_neon_address: Optional[PublicKey] = None
        self.eth_accounts: List[AccountMeta] = []
        self.eth_tx: Optional[EthTx] = None
        self.msg: Optional[bytes] = None
        self.holder_msg: Optional[bytes] = None
        self.collateral_pool_index_buf: Optional[bytes] = None
        self.collateral_pool_address: Optional[PublicKey] = None
        self.storage: Optional[PublicKey] = None
        self.holder: Optional[PublicKey] = None
        self.perm_accs_id: Optional[int] = None

    def init_operator_ether(self, operator_ether: EthereumAddress):
        self.operator_neon_address = ether2program(operator_ether)[0]

    def init_eth_tx(self, eth_tx: EthTx):
        self.eth_tx = eth_tx

        self.msg = bytes.fromhex(self.eth_tx.sender()) + self.eth_tx.signature() + self.eth_tx.unsigned_msg()
        self.holder_msg = get_holder_msg(self.eth_tx)

        keccak_result = keccak_256(self.eth_tx.unsigned_msg()).digest()
        collateral_pool_index = int().from_bytes(keccak_result[:4], "little") % COLLATERALL_POOL_MAX
        self.collateral_pool_index_buf = collateral_pool_index.to_bytes(4, 'little')
        self.collateral_pool_address = self.create_collateral_pool_address(collateral_pool_index)

        return self

    def init_eth_accounts(self, eth_accounts: List[AccountMeta]):
        self.eth_accounts = eth_accounts

    def init_iterative(self, storage: PublicKey, holder: Optional[PublicKey], perm_accs_id: int):
        self.storage = storage
        self.holder = holder
        self.perm_accs_id = perm_accs_id

        return self

    @staticmethod
    def create_collateral_pool_address(collateral_pool_index):
        COLLATERAL_SEED_PREFIX = "collateral_seed_"
        seed = COLLATERAL_SEED_PREFIX + str(collateral_pool_index)
        collateral_pool_base = PublicKey(ElfParams().collateral_pool_base)
        return accountWithSeed(bytes(collateral_pool_base), str.encode(seed))

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

    def create_refund_instruction(self, refunded_account: PublicKey, seed: bytes) -> TransactionInstruction:
        seed_str = str(seed, 'utf8')
        self.debug(f"createRefundTrx {self.operator_account} refunded account({refunded_account}) seed({seed_str})")
        return TransactionInstruction(
            keys=[
                AccountMeta(pubkey=refunded_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
            ],
            program_id=EVM_LOADER_ID,
            data=bytearray.fromhex("10") + seed,
        )

    def make_create_eth_account_instruction(self, eth_address: EthereumAddress, code_acc=None) -> TransactionInstruction:
        if isinstance(eth_address, str):
            eth_address = EthereumAddress(eth_address)
        pda_account, nonce = ether2program(eth_address)
        self.debug(f'Create eth account: {str(eth_address)}, sol account: {pda_account}, nonce: {nonce}')

        base = self.operator_account
        data = create_account_layout(bytes(eth_address), nonce)
        if code_acc is None:
            return TransactionInstruction(
                program_id=EVM_LOADER_ID,
                data=data,
                keys=[
                    AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                    AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=pda_account, is_signer=False, is_writable=True),
                ])
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=base, is_signer=True, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=pda_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=PublicKey(code_acc), is_signer=False, is_writable=True),
            ])

    def make_erc20token_account_instruction(self, token_info) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.ERC20CreateTokenAccount.value,
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
            data=EvmInstruction.ResizeContractAccount.value + bytes(seed),  # 17- ResizeStorageAccount
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
            data=EvmInstruction.CallFromRawEthereumTX.value + self.collateral_pool_index_buf + self.msg,
            keys=[
                AccountMeta(pubkey=SYSVAR_INSTRUCTION_PUBKEY, is_signer=False, is_writable=False),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.collateral_pool_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_neon_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=EVM_LOADER_ID, is_signer=False, is_writable=False),
            ] + self.eth_accounts
        )

    def make_noniterative_call_transaction(self, length_before: int) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_tx.unsigned_msg()), 5))
        trx.add(self.make_05_call_instruction())
        return trx

    def make_cancel_instruction(self, storage_account: Optional[PublicKey] = None,
                                nonce: Optional[int] = None,
                                cancel_key_list: Optional[List[AccountMeta]] = None) -> TransactionInstruction:
        append_key_list: List[AccountMeta] = self.eth_accounts if cancel_key_list is None else cancel_key_list
        if nonce is None:
            nonce = self.eth_tx.nonce
        if storage_account is None:
            storage_account = self.storage
        return TransactionInstruction(
            program_id=EVM_LOADER_ID,
            data=EvmInstruction.CancelWithNonce.value + nonce.to_bytes(8, 'little'),
            keys=[
                AccountMeta(pubkey=storage_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),
                AccountMeta(pubkey=INCINERATOR_PUBKEY, is_signer=False, is_writable=True),
            ] + append_key_list
        )

    def make_partial_call_or_continue_instruction(self, steps: int) -> TransactionInstruction:
        data = EvmInstruction.PartialCallOrContinueFromRawEthereumTX.value + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder="little") + self.msg
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
            ] + self.eth_accounts
        )

    def make_partial_call_or_continue_transaction(self, steps: int, length_before: int) -> Transaction:
        trx = Transaction()
        trx.add(self.make_keccak_instruction(length_before + 1, len(self.eth_tx.unsigned_msg()), 13))
        trx.add(self.make_partial_call_or_continue_instruction(steps))
        return trx

    def _make_partial_call_or_continue_from_account_data(self,
                                                         ix_id_byte: bytes,
                                                         steps: int,
                                                         index: int) -> TransactionInstruction:
        data = ix_id_byte + self.collateral_pool_index_buf + steps.to_bytes(8, byteorder='little')
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
                 ] + self.eth_accounts
        )

    def make_partial_call_or_continue_from_account_data_instruction(self,
                                                                    steps: int,
                                                                    index: int) -> TransactionInstruction:
        return self._make_partial_call_or_continue_from_account_data(
            EvmInstruction.ExecuteTrxFromAccountDataIterativeOrContinue.value,
            steps,
            index
        )

    def make_partial_call_or_continue_from_account_data_no_chainid_instruction(self,
                                                                               steps: int,
                                                                               index: int) -> TransactionInstruction:
        return self._make_partial_call_or_continue_from_account_data(
            EvmInstruction.ExecuteTrxFromAccountDataIterativeOrContinueNoChainId.value,
            steps,
            index
        )

    def make_create_lookup_table_instruction(self, table_account: PublicKey,
                                             recent_block_slot: int,
                                             seed: int) -> TransactionInstruction:
        data = int(0).to_bytes(4, byteorder="little")
        data += recent_block_slot.to_bytes(8, byteorder="little")
        data += seed.to_bytes(1, byteorder="little")
        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),  # signer
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),   # payer
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        )

    def make_extend_lookup_table_instruction(self, table_account: PublicKey,
                                             account_list: List[PublicKey]) -> TransactionInstruction:
        data = int(2).to_bytes(4, byteorder="little")
        data += len(account_list).to_bytes(8, byteorder="little")
        data += b"".join([bytes(pubkey) for pubkey in account_list])

        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),  # signer
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=True),   # payer
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
            ]
        )

    def make_deactivate_lookup_table_instruction(self, table_account: PublicKey) -> TransactionInstruction:
        data = int(3).to_bytes(4, byteorder="little")
        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),  # signer
            ]
        )

    def make_close_lookup_table_instruction(self, table_account: PublicKey) -> TransactionInstruction:
        data = int(4).to_bytes(4, byteorder="little")
        return TransactionInstruction(
            program_id=ADDRESS_LOOKUP_TABLE_ID,
            data=data,
            keys=[
                AccountMeta(pubkey=table_account, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.operator_account, is_signer=True, is_writable=False),  # signer
                AccountMeta(pubkey=self.operator_account, is_signer=False, is_writable=True),  # refund
            ]
        )
