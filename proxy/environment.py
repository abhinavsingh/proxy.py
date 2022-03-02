import sys
from decimal import Decimal
import json
import os
import subprocess
from logged_groups import logged_group, LogMng
from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
from typing import Optional, List

from proxy.common_neon.address import EthereumAddress

SOLANA_URL = os.environ.get("SOLANA_URL", "http://localhost:8899")
PP_SOLANA_URL = os.environ.get("PP_SOLANA_URL", SOLANA_URL)
EVM_LOADER_ID = os.environ.get("EVM_LOADER")
neon_cli_timeout = float(os.environ.get("NEON_CLI_TIMEOUT", "0.1"))

CONFIRMATION_CHECK_DELAY = float(os.environ.get("NEON_CONFIRMATION_CHECK_DELAY", "0.1"))
CONTINUE_COUNT_FACTOR = int(os.environ.get("CONTINUE_COUNT_FACTOR", "3"))
TIMEOUT_TO_RELOAD_NEON_CONFIG = int(os.environ.get("TIMEOUT_TO_RELOAD_NEON_CONFIG", "3600"))

MINIMAL_GAS_PRICE=os.environ.get("MINIMAL_GAS_PRICE", None)
if MINIMAL_GAS_PRICE is not None:
    MINIMAL_GAS_PRICE = int(MINIMAL_GAS_PRICE)*10**9

GAS_PRICE_SUGGESTED_PCT = Decimal(os.environ.get("GAS_PRICE_SUGGEST_PCT", "0.02"))

EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "0"))
LOG_SENDING_SOLANA_TRANSACTION = os.environ.get("LOG_SENDING_SOLANA_TRANSACTION", "NO") == "YES"
LOG_NEON_CLI_DEBUG = os.environ.get("LOG_NEON_CLI_DEBUG", "NO") == "YES"
WRITE_TRANSACTION_COST_IN_DB = os.environ.get("WRITE_TRANSACTION_COST_IN_DB", "NO") == "YES"
RETRY_ON_FAIL = int(os.environ.get("RETRY_ON_FAIL", "10"))
RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION = max(int(os.environ.get("RETRY_ON_FAIL_ON_GETTING_CONFIRMED_TRANSACTION", "1000")), 1)
FUZZING_BLOCKHASH = os.environ.get("FUZZING_BLOCKHASH", "NO") == "YES"
CONFIRM_TIMEOUT = max(int(os.environ.get("CONFIRM_TIMEOUT", 10)), 10)
PARALLEL_REQUESTS = int(os.environ.get("PARALLEL_REQUESTS", "2"))
DEVNET_HISTORY_START = "7BdwyUQ61RUZP63HABJkbW66beLk22tdXnP69KsvQBJekCPVaHoJY47Rw68b3VV1UbQNHxX3uxUSLfiJrfy2bTn"
HISTORY_START = [DEVNET_HISTORY_START]
START_SLOT = os.environ.get('START_SLOT', 0)
FINALIZED = os.environ.get('FINALIZED', 'finalized')
CANCEL_TIMEOUT = int(os.environ.get("CANCEL_TIMEOUT", "60"))
ACCOUNT_PERMISSION_UPDATE_INT = int(os.environ.get("ACCOUNT_PERMISSION_UPDATE_INT", 60 * 5))
PERM_ACCOUNT_LIMIT = max(int(os.environ.get("PERM_ACCOUNT_LIMIT", 2)), 2)
OPERATOR_FEE = Decimal(os.environ.get("OPERATOR_FEE", "0.1"))
OPERATOR_GAS_ACCOUNTS = os.environ.get('OPERATOR_GAS_ACCOUNTS', '0x8966Ef2ae7A109Fd0977F5151b4607dc42929fBD;0x619d670152103a972B67a45b9Be764FF11979E4E')
NEON_PRICE_USD = Decimal('0.25')
SOL_PRICE_UPDATE_INTERVAL = int(os.environ.get("SOL_PRICE_UPDATE_INTERVAL", 60))
GET_SOL_PRICE_MAX_RETRIES = int(os.environ.get("GET_SOL_PRICE_MAX_RETRIES", 3))
GET_SOL_PRICE_RETRY_INTERVAL = int(os.environ.get("GET_SOL_PRICE_RETRY_INTERVAL", 1))
INDEXER_LOG_SKIP_COUNT = int(os.environ.get("INDEXER_LOG_SKIP_COUNT", 10))
MIN_OPERATOR_BALANCE_TO_WARN = max(int(os.environ.get("MIN_OPERATOR_BALANCE_TO_WARN", 9000000000)), 9000000000)
MIN_OPERATOR_BALANCE_TO_ERR = max(int(os.environ.get("MIN_OPERATOR_BALANCE_TO_ERR", 1000000000)), 1000000000)
SKIP_PREFLIGHT = os.environ.get("SKIP_PREFLIGHT", "NO") == "YES"
CONTRACT_EXTRA_SPACE = int(os.environ.get("CONTRACT_EXTRA_SPACE", 2048))

PYTH_MAPPING_ACCOUNT = os.environ.get("PYTH_MAPPING_ACCOUNT", None)
if PYTH_MAPPING_ACCOUNT is not None:
    PYTH_MAPPING_ACCOUNT = PublicKey(PYTH_MAPPING_ACCOUNT)

class CliBase:

    def run_cli(self, cmd: List[str], **kwargs) -> bytes:
        self.debug("Calling: " + " ".join(cmd))
        proc_result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        if proc_result.stderr is not None:
            print(proc_result.stderr, file=sys.stderr)
        return proc_result.stdout


@logged_group("neon.Proxy")
class solana_cli(CliBase):
    def call(self, *args):
        try:
            cmd = ["solana",
                   "--url", SOLANA_URL,
                   ] + list(args)
            self.debug("Calling: " + " ".join(cmd))
            return self.run_cli(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            self.error("ERR: solana error {}".format(err))
            raise


@logged_group("neon.Proxy")
def get_solana_accounts(*, logger) -> [SolanaAccount]:
    def read_sol_account(name) -> Optional[SolanaAccount]:
        if not os.path.isfile(name):
            return None

        with open(name.strip(), mode='r') as d:
            pkey = (d.read())
            num_list = [int(v) for v in pkey.strip("[] \n").split(',')]
            value_list = bytes(num_list[0:32])
            return SolanaAccount(value_list)

    res = solana_cli().call('config', 'get')
    substr = "Keypair Path: "
    path = ""
    for line in res.splitlines():
        if line.startswith(substr):
            path = line[len(substr):].strip()
    if path == "":
        raise Exception("cannot get keypair path")

    path = path.strip()

    signer_list = []
    (file_name, file_ext) = os.path.splitext(path)
    i = 0
    while True:
        i += 1
        full_path = file_name + (str(i) if i > 1 else '') + file_ext
        signer = read_sol_account(full_path)
        if not signer:
            break
        signer_list.append(signer)
        logger.debug(f'Add signer: {signer.public_key()}')

    if not len(signer_list):
        raise Exception("No keypairs")

    return signer_list

@logged_group("neon.Proxy")
def get_operator_ethereum_accounts(*, logger) -> [EthereumAddress]:
    accounts = []

    for account in OPERATOR_GAS_ACCOUNTS.split(';'):
        address = EthereumAddress(account)
        logger.debug(f'Add gas account: {address}')

        accounts.append(address)

    return accounts

@logged_group("neon.Proxy")
class neon_cli(CliBase):

    def call(self, *args):
        try:
            ctx = json.dumps(LogMng.get_logging_context())
            cmd = ["neon-cli",
                   "--commitment=recent",
                   "--url", SOLANA_URL,
                   f"--evm_loader={EVM_LOADER_ID}",
                   f"--logging_ctx={ctx}"
                   ]\
                  + (["-vvv"] if LOG_NEON_CLI_DEBUG else [])\
                  + list(args)
            return self.run_cli(cmd, timeout=neon_cli_timeout, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            self.error("ERR: neon-cli error {}".format(err))
            raise

    def version(self):
        try:
            cmd = ["neon-cli", "--version"]
            return self.run_cli(cmd, timeout=neon_cli_timeout, universal_newlines=True).split()[1]
        except subprocess.CalledProcessError as err:
            self.error("ERR: neon-cli error {}".format(err))
            raise


def read_elf_params(out_dict):
    for param in neon_cli().call("neon-elf-params").splitlines():
        if param.startswith('NEON_') and '=' in param:
            v = param.split('=')
            out_dict[v[0]] = v[1]


ELF_PARAMS = {}
read_elf_params(ELF_PARAMS)
COLLATERAL_POOL_BASE = ELF_PARAMS.get("NEON_POOL_BASE")
ETH_TOKEN_MINT_ID: PublicKey = PublicKey(ELF_PARAMS.get("NEON_TOKEN_MINT"))
HOLDER_MSG_SIZE = int(ELF_PARAMS.get("NEON_HOLDER_MSG_SIZE"))
CHAIN_ID = int(ELF_PARAMS.get('NEON_CHAIN_ID', None))