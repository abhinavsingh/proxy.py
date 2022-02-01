from lib2to3.pgen2 import token
from spl.token.client import Token as SplToken
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import get_associated_token_address
from proxy.common_neon.address import EthereumAddress, ether2program
from typing import Union
from solana.rpc.commitment import Confirmed
from solana.transaction import Transaction
from solana.rpc.types import TxOpts
import spl.token.instructions as spl_token
from proxy.common_neon.utils import get_from_dict
from decimal import Decimal
import os

class PermissionToken:
    def __init__(self,
                 solana: SolanaClient,
                 token_mint: PublicKey,
                 payer: SolanaAccount):
        self.solana = solana
        self.token_mint = token_mint
        self.payer = payer
        self.token = SplToken(self.solana,
                              self.token_mint,
                              TOKEN_PROGRAM_ID,
                              payer)

    def get_token_account_address(self, ether_addr: Union[str, EthereumAddress]):
        sol_addr = PublicKey(ether2program(ether_addr)[0])
        return get_associated_token_address(sol_addr, self.token.pubkey)

    def get_balance(self, ether_addr: Union[str, EthereumAddress]):
        token_account = self.get_token_account_address(ether_addr)
        result = self.token.get_balance(token_account).get('result', None)
        if result is None:
            return 0
        return int(result['value']['amount'])

    def create_account_if_needed(self,
                                 ether_addr: Union[str, EthereumAddress]):
        token_account = self.get_token_account_address(ether_addr)
        response = self.solana.get_account_info(token_account, Confirmed)
        if get_from_dict(response, 'result', 'value') is not None:
            return token_account

        txn = Transaction()
        create_txn = spl_token.create_associated_token_account(
            payer=self.payer.public_key(),
            owner=PublicKey(ether2program(ether_addr)[0]),
            mint=self.token.pubkey
        )
        txn.add(create_txn)
        self.token._conn.send_transaction(txn, self.payer, opts=TxOpts(skip_preflight=True, skip_confirmation=False))
        return token_account

    def mint_to(self,
                amount: int,
                ether_addr: Union[str, EthereumAddress],
                mint_authority_file: str):
        token_account = self.create_account_if_needed(ether_addr)
        mint_command = f'spl-token mint "{str(self.token.pubkey)}" {Decimal(amount) * pow(Decimal(10), -9)}'
        mint_command += f' --owner {mint_authority_file} -- "{str(token_account)}"'
        os.system(mint_command)
