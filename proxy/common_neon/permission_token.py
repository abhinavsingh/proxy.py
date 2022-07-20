from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
from spl.token.instructions import get_associated_token_address
from proxy.common_neon.address import EthereumAddress, ether2program
from typing import Union
import spl.token.instructions as spl_token
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.common_neon.solana_tx_list_sender import SolTxListSender
from decimal import Decimal
import os
from .compute_budget import TransactionWithComputeBudget


class PermissionToken:
    def __init__(self, solana: SolanaInteractor, token_mint: PublicKey):
        self.solana = solana
        self.waiter = None
        self.token_mint = token_mint

    def get_token_account_address(self, ether_addr: Union[str, EthereumAddress]):
        sol_addr = ether2program(ether_addr)[0]
        return get_associated_token_address(sol_addr, self.token_mint)

    def get_balance(self, ether_addr: Union[str, EthereumAddress]):
        token_account = self.get_token_account_address(ether_addr)
        return self.solana.get_token_account_balance(token_account)

    def create_account_if_needed(self, ether_addr: Union[str, EthereumAddress], signer: SolanaAccount):
        token_account = self.get_token_account_address(ether_addr)
        info = self.solana.get_account_info(token_account)
        if info is not None:
            return token_account

        txn = TransactionWithComputeBudget()
        create_txn = spl_token.create_associated_token_account(
            payer=signer.public_key(),
            owner=ether2program(ether_addr)[0],
            mint=self.token_mint
        )
        txn.add(create_txn)
        SolTxListSender(self.solana, signer).send('CreateAssociatedTokenAccount(1)', [txn], skip_preflight=True)
        return token_account

    def mint_to(self, amount: int, ether_addr: Union[str, EthereumAddress], mint_authority_file: str, signer: SolanaAccount):
        token_account = self.create_account_if_needed(ether_addr, signer)
        mint_command = f'spl-token mint "{str(self.token_mint)}" {Decimal(amount) * pow(Decimal(10), -9)}'
        mint_command += f' --owner {mint_authority_file} -- "{str(token_account)}"'
        os.system(mint_command)
