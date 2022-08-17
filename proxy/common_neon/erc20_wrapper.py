from solcx import install_solc
from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID
from eth_account.signers.local import LocalAccount as NeonAccount
from solana.rpc.api import Account as SolanaAccount
from solana.publickey import PublicKey
from solana.transaction import AccountMeta, TransactionInstruction
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY
from solana.rpc.types import TxOpts, RPCResponse, Commitment
import spl.token.instructions as spl_token
from typing import Union, Dict
import struct
from logged_groups import logged_group
from .compute_budget import TransactionWithComputeBudget
from sha3 import keccak_256
from proxy.common_neon.eth_proto import Trx
from ..common_neon.neon_instruction import NeonIxBuilder
from ..common_neon.web3 import NeonWeb3
from proxy.common_neon.address import EthereumAddress

install_solc(version='0.7.6')
from solcx import compile_source

# Standard interface of ERC20 contract to generate ABI for wrapper
ERC20FORSPL_INTERFACE_SOURCE = '''
pragma solidity >=0.7.0;

interface IERC20ForSpl {

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    event ApprovalSolana(address indexed owner, bytes32 indexed spender, uint64 amount);
    event TransferSolana(address indexed from, bytes32 indexed to, uint64 amount);

    function name() external  view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenMint() external view returns (bytes32);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function burn(uint256 amount) external returns (bool);
    function burnFrom(address from, uint256 amount) external returns (bool);
    function approveSolana(bytes32 spender, uint64 amount) external returns (bool);
    function transferSolana(bytes32 to, uint64 amount) external returns (bool);
    function claim(bytes32 from, uint64 amount) external returns (bool);
}

'''

@logged_group("neon.Proxy")
class ERC20Wrapper:
    proxy: NeonWeb3
    name: str
    symbol: str
    token: Token
    admin: NeonAccount
    mint_authority: SolanaAccount
    evm_loader_id: PublicKey
    neon_contract_address: str
    solana_contract_address: PublicKey
    interface: Dict
    wrapper: Dict

    def __init__(self, proxy: NeonWeb3,
                 name: str, symbol: str,
                 token: Token,
                 admin: NeonAccount,
                 mint_authority: SolanaAccount,
                 evm_loader_id: PublicKey):
        self.proxy = proxy
        self.name = name
        self.symbol = symbol
        self.token = token
        self.admin = admin
        self.mint_authority = mint_authority
        self.evm_loader_id = evm_loader_id

    def get_neon_account_address(self, neon_account_address: str) -> PublicKey:
        neon_account_addressbytes = bytes.fromhex(neon_account_address[2:])
        return PublicKey.find_program_address([b"\1", neon_account_addressbytes], self.evm_loader_id)[0]

    def deploy_wrapper(self):
        compiled_interface = compile_source(ERC20FORSPL_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        with open('/opt/contracts/erc20_for_spl.sol', 'r') as file:
            source = file.read()
        compiled_wrapper = compile_source(source)
        wrapper_interface = compiled_wrapper["<stdin>:ERC20ForSpl"]
        self.wrapper = wrapper_interface

        erc20 = self.proxy.eth.contract(abi=self.wrapper['abi'], bytecode=wrapper_interface['bin'])
        nonce = self.proxy.eth.get_transaction_count(self.proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor(self.name, self.symbol, bytes(self.token.pubkey)).buildTransaction(tx)
        tx_deploy = self.proxy.eth.account.sign_transaction(tx_constructor, self.admin.key)
        tx_deploy_hash = self.proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        self.debug(f'tx_deploy_hash: {tx_deploy_hash.hex()}')
        tx_deploy_receipt = self.proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        self.debug(f'tx_deploy_receipt: {tx_deploy_receipt}')
        self.debug(f'deploy status: {tx_deploy_receipt.status}')
        self.neon_contract_address = tx_deploy_receipt.contractAddress
        self.solana_contract_address = self.get_neon_account_address(self.neon_contract_address)

    def get_neon_erc20_account_address(self, neon_account_address: str):
        neon_contract_address_bytes = bytes.fromhex(self.neon_contract_address[2:])
        neon_account_address_bytes = bytes.fromhex(neon_account_address[2:])
        seeds = [b"\1", b"ERC20Balance",
                 bytes(self.token.pubkey),
                 neon_contract_address_bytes,
                 neon_account_address_bytes]
        return PublicKey.find_program_address(seeds, self.evm_loader_id)[0]

    def create_associated_token_account(self, owner: PublicKey, payer: SolanaAccount):
        # Construct transaction
        # This part of code is based on original implementation of Token.create_associated_token_account
        # except that skip_preflight is set to True
        tx = TransactionWithComputeBudget()
        create_ix = spl_token.create_associated_token_account(
            payer=payer.public_key(), owner=owner, mint=self.token.pubkey
        )
        tx.add(create_ix)
        self.token._conn.send_transaction(tx, payer, opts=TxOpts(skip_preflight = True, skip_confirmation=False))
        return create_ix.keys[1].pubkey

    def create_claim_instruction(self, owner: PublicKey, from_acc: PublicKey, to_acc: NeonAccount, amount: int):
        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.wrapper['abi'])
        nonce = self.proxy.eth.get_transaction_count(to_acc.address)
        claim_tx = erc20.functions.claim(bytes(from_acc), amount).buildTransaction({'nonce': nonce, 'gasPrice': 0})
        claim_tx = self.proxy.eth.account.sign_transaction(claim_tx, to_acc.key)

        eth_trx = bytearray.fromhex(claim_tx.rawTransaction.hex()[2:])
        emulating_result = self.proxy.neon.emulate(eth_trx)

        eth_accounts = dict()
        for account in emulating_result['accounts']:
            key = account['account']
            eth_accounts[key] = AccountMeta(pubkey=PublicKey(key), is_signer=False, is_writable=True)
            if account['contract']:
                key = account['contract']
                eth_accounts[key] = AccountMeta(pubkey=PublicKey(key), is_signer=False, is_writable=True)

        for account in emulating_result['solana_accounts']:
            key = account['pubkey']
            eth_accounts[key] = AccountMeta(pubkey=PublicKey(key), is_signer=False, is_writable=True)

        eth_accounts = list(eth_accounts.values())

        neon = NeonIxBuilder(owner)
        neon.init_operator_ether(EthereumAddress(to_acc.address))
        neon.init_eth_tx(Trx.fromString(eth_trx))
        neon.init_eth_accounts(eth_accounts)
        return neon

    def create_input_liquidity_instruction(self, payer: PublicKey, from_address: PublicKey, to_address: str, amount: int):
        return TransactionInstruction(
            program_id=TOKEN_PROGRAM_ID,
            data=b'\3' + struct.pack('<Q', amount),
            keys=[
                AccountMeta(pubkey=from_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.get_neon_erc20_account_address(to_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=payer, is_signer=True, is_writable=False)
            ]
        )

    def mint_to(self, destination: Union[PublicKey, str], amount: int) -> RPCResponse:
        """
        Method mints given amount of tokens to a given address - either in NEON or Solana format
        NOTE: destination account must be previously created
        """
        if isinstance(destination, str):
            destination = self.get_neon_erc20_account_address(destination)
        return self.token.mint_to(destination, self.mint_authority, amount,
                                  opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def erc20_interface(self):
        return self.proxy.eth.contract(address=self.neon_contract_address, abi=self.interface['abi'])

    def get_balance(self, address: Union[PublicKey, str]) -> int:
        if isinstance(address, PublicKey):
            return int(self.token.get_balance(address, Commitment('confirmed'))['result']['value']['amount'])

        erc20 = self.proxy.eth.contract(address=self.neon_contract_address, abi=self.interface['abi'])
        return erc20.functions.balanceOf(address).call()
