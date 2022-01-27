from datetime import datetime
from proxy.environment import ELF_PARAMS
from proxy.common_neon.permission_token import PermissionToken
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from typing import Union
from proxy.common_neon.address import EthereumAddress
from logged_groups import logged_group

NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE = int(ELF_PARAMS.get("NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE", 0))
NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE = int(ELF_PARAMS.get("NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE", 0))

@logged_group("neon.AccountWhitelist")
class AccountWhitelist:
    def __init__(self, solana: SolanaClient, payer: SolanaAccount, permission_update_int: int):
        self.solana = solana
        self.account_cache = {}
        self.permission_update_int = permission_update_int
        allowance_token_addr = ELF_PARAMS.get("NEON_PERMISSION_ALLOWANCE_TOKEN", '')
        if allowance_token_addr != '':
            self.allowance_token = PermissionToken(self.solana,
                                                   PublicKey(allowance_token_addr),
                                                   payer)

        denial_token_addr = ELF_PARAMS.get("NEON_PERMISSION_DENIAL_TOKEN", '')
        if denial_token_addr != '':
            self.denial_token = PermissionToken(self.solana,
                                                PublicKey(denial_token_addr),
                                                payer)

        if self.allowance_token is None and self.denial_token is None:
            return

        if self.allowance_token is None or self.denial_token is None:
            self.error(f'Wrong proxy configuration: allowance and denial tokens must both exist or absent!')
            raise Exception("NEON service is unhealthy. Try again later")

    def read_balance_diff(self, ether_addr: Union[str, EthereumAddress]):
        allowance_balance = self.allowance_token.get_balance(ether_addr)
        denial_balance = self.denial_token.get_balance(ether_addr)
        return allowance_balance - denial_balance

    def grant_permissions(self, ether_addr: Union[str, EthereumAddress], min_balance: int):
        try:
            diff = self.read_balance_diff(ether_addr)
            if diff >= min_balance:
                self.info(f'{ether_addr} already has permission')
                return True

            to_mint = min_balance - diff
            self.allowance_token.mint_to(to_mint, ether_addr)
            self.info(f'Permissions granted to {ether_addr}')
            return True
        except Exception as err:
            self.error(f'Failed to grant permissions to {ether_addr}: {err}')
            return False

    def deprive_permissions(self, ether_addr: Union[str, EthereumAddress], min_balance: int):
        try:
            diff = self.read_balance_diff(ether_addr)
            if diff < min_balance:
                self.info(f'{ether_addr} already deprived')
                return True

            to_mint = diff - min_balance + 1
            self.denial_token.mint_to(to_mint, ether_addr)
            self.info(f'Permissions deprived to {ether_addr}')
            return True
        except Exception as err:
            self.error(f'Failed to grant permissions to {ether_addr}: {err}')
            return False

    def grant_client_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.grant_permissions(ether_addr, NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE)

    def grant_contract_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.grant_permissions(ether_addr, NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE)

    def deprive_client_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.deprive_permissions(ether_addr, NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE)

    def deprive_contract_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.deprive_permissions(ether_addr, NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE)

    def get_current_time(self):
        return datetime.now().timestamp()

    def has_permission(self, ether_addr: Union[str, EthereumAddress], min_balance: int):
        if self.allowance_token is None and self.denial_token is None:
            return True

        cached = self.account_cache.get(ether_addr, None)
        current_time = self.get_current_time()
        if cached is not None:
            diff = current_time - cached['last_update']
            if diff < self.permission_update_int:
                return cached['diff'] >= min_balance

        try:
            diff = self.read_balance_diff(ether_addr)
            self.account_cache[ether_addr] = { 
                'last_update': current_time, 
                'diff': diff 
            }
            return diff >= min_balance
        except Exception as err:
            self.error(f'Failed to read permissions for {ether_addr}: {err}')
            raise RuntimeError('Failed to read account permissions. Try to repeat later')

    def has_client_permission(self, ether_addr: Union[str, EthereumAddress]):
        return self.has_permission(ether_addr, NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE)

    def has_contract_permission(self, ether_addr: Union[str, EthereumAddress]):
        return self.has_permission(ether_addr, NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE)
