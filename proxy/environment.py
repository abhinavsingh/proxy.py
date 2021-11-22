import os
import subprocess
import logging
from solana.publickey import PublicKey

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

solana_url = os.environ.get("SOLANA_URL", "http://localhost:8899")
evm_loader_id = os.environ.get("EVM_LOADER")
neon_cli_timeout = float(os.environ.get("NEON_CLI_TIMEOUT", "0.1"))

class solana_cli:
    def call(self, *args):
        try:
            cmd = ["solana",
                   "--url", solana_url,
                   ] + list(args)
            logger.debug("Calling: " + " ".join(cmd))
            return subprocess.check_output(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            logger.debug("ERR: solana error {}".format(err))
            raise


class neon_cli:
    def call(self, *args):
        try:
            cmd = ["neon-cli",
                   "--commitment=recent",
                   "--url", solana_url,
                   "--evm_loader={}".format(evm_loader_id),
                   ] + list(args)
            logger.debug("Calling: " + " ".join(cmd))
            return subprocess.check_output(cmd, timeout=neon_cli_timeout, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            logger.debug("ERR: neon-cli error {}".format(err))
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
