from __future__ import annotations

from typing import Optional, Dict, Any

from logged_groups import logged_group
from singleton_decorator import singleton

from solana.publickey import PublicKey

from .environment_utils import neon_cli


@singleton
class ElfParams:

    def __init__(self):
        self.elf_params = {}
        read_elf_params(self.elf_params)

    @property
    def collateral_pool_base(self) -> Optional[str]:
        return self.elf_params.get("NEON_POOL_BASE")

    @property
    def neon_heap_frame(self) -> int:
        return int(self.elf_params.get("NEON_HEAP_FRAME"))

    @property
    def neon_compute_units(self) -> int:
        return int(self.elf_params.get("NEON_COMPUTE_UNITS"))

    @property
    def neon_additional_fee(self):
        return int(self.elf_params.get("NEON_ADDITIONAL_FEE"))

    @property
    def neon_token_mint(self) -> PublicKey:
        return PublicKey(self.elf_params.get("NEON_TOKEN_MINT"))

    @property
    def chain_id(self) -> int:
        return int(self.elf_params.get('NEON_CHAIN_ID'))

    @property
    def holder_msg_size(self) -> int:
        return int(self.elf_params.get("NEON_HOLDER_MSG_SIZE"))

    @property
    def neon_evm_version(self) -> Optional[str]:
        return self.elf_params.get("NEON_PKG_VERSION")

    @property
    def neon_evm_revision(self) -> Optional[str]:
        return self.elf_params.get('NEON_REVISION')

    @property
    def neon_gas_limit_multiplier_no_chainid(self) -> int:
        return int(self.elf_params.get('NEON_GAS_LIMIT_MULTIPLIER_NO_CHAINID'))

    @property
    def neon_minimal_client_allowance_balance(self) -> int:
        return int(self.elf_params.get("NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE", 0))

    @property
    def neon_minimal_contract_allowance_balance(self) -> int:
        return int(self.elf_params.get("NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE", 0))

    @property
    def allowance_token_addr(self) -> str:
        return self.elf_params.get("NEON_PERMISSION_ALLOWANCE_TOKEN", '')

    @property
    def denial_token_addr(self) -> str:
        return self.elf_params.get("NEON_PERMISSION_DENIAL_TOKEN", '')

    def get_params(self) -> Dict[str: Any]:
        return self.elf_params


@logged_group("neon.Proxy")
def read_elf_params(out_dict, *, logger):
    logger.debug("Read ELF params")
    for param in neon_cli().call("neon-elf-params").splitlines():
        if param.startswith('NEON_') and '=' in param:
            v = param.split('=')
            out_dict[v[0]] = v[1]
            logger.debug(f"ELF param: {v[0]}: {v[1]}")
