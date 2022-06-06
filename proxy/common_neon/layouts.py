
from construct import Bytes, Int8ul, Int32ul, Int64ul
from construct import Struct

STORAGE_ACCOUNT_INFO_LAYOUT = Struct(
    "tag" / Int8ul,
    "caller" / Bytes(20),
    "nonce" / Int64ul,
    "gas_limit" / Bytes(32),
    "gas_price" / Bytes(32),
    "slot" / Int64ul,
    "operator" / Bytes(32),
    "account_list_len" / Int64ul,
    "executor_data_size" / Int64ul,
    "evm_data_size" / Int64ul,
    "gas_used_and_paid" / Bytes(32),
    "number_of_payments" / Int64ul,
    "sign" / Bytes(65),
)

ACCOUNT_INFO_LAYOUT = Struct(
    "type" / Int8ul,
    "ether" / Bytes(20),
    "nonce" / Int8ul,
    "trx_count" / Bytes(8),
    "balance" / Bytes(32),
    "code_account" / Bytes(32),
    "is_rw_blocked" / Int8ul,
    "ro_blocked_cnt" / Int8ul,
)

CODE_ACCOUNT_INFO_LAYOUT = Struct(
    "type" / Int8ul,
    "owner" / Bytes(32),
    "code_size" / Int32ul,
    "generation" / Int32ul,
)


CREATE_ACCOUNT_LAYOUT = Struct(
    "ether" / Bytes(20),
    "nonce" / Int8ul
)
