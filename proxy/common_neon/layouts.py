
from construct import Bytes, Int8ul, Int32ul, Int64ul
from construct import Struct

STORAGE_ACCOUNT_INFO_LAYOUT = Struct(
    # "tag" / Int8ul,
    "caller" / Bytes(20),
    "nonce" / Int64ul,
    "gas_limit" / Int64ul,
    "gas_price" / Int64ul,
    "slot" / Int64ul,
    "operator" / Bytes(32),
    "accounts_len" / Int64ul,
    "executor_data_size" / Int64ul,
    "evm_data_size" / Int64ul,
    "gas_used_and_paid" / Int64ul,
    "number_of_payments" / Int64ul,
    "sign" / Bytes(65),
)

ACCOUNT_INFO_LAYOUT = Struct(
    "type" / Int8ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul,
    "trx_count" / Bytes(8),
    "code_account" / Bytes(32),
    "is_rw_blocked" / Int8ul,
    "rw_blocked_acc" / Bytes(32),
    "eth_token_account" / Bytes(32),
    "ro_blocked_cnt" / Int8ul,
    "state" / Int8ul,
)

CODE_ACCOUNT_INFO_LAYOUT = Struct(
    "type" / Int8ul,
    "owner" / Bytes(32),
    "code_size" / Int32ul,
)


CREATE_ACCOUNT_LAYOUT = Struct(
    "lamports" / Int64ul,
    "space" / Int64ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul
)
