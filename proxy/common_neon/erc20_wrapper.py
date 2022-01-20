from solcx import install_solc
from web3 import Web3
from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID
from eth_account.signers.local import LocalAccount as NeonAccount
from solana.rpc.api import Account as SolanaAccount
from solana.publickey import PublicKey
from solana.transaction import AccountMeta, TransactionInstruction
from solana.system_program import SYS_PROGRAM_ID
from solana.sysvar import SYSVAR_RENT_PUBKEY
from solana.rpc.types import TxOpts, RPCResponse, Commitment
from solana.transaction import Transaction
import spl.token.instructions as spl_token
from typing import Union, Dict
import struct
from logged_groups import logged_group

install_solc(version='0.7.6')
from solcx import compile_source

# Standard interface of ERC20 contract to generate ABI for wrapper
ERC20_INTERFACE_SOURCE = '''
pragma solidity >=0.7.0;

interface IERC20 {
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function approve(address spender, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);


    function approveSolana(bytes32 spender, uint64 value) external returns (bool);
    event ApprovalSolana(address indexed owner, bytes32 indexed spender, uint64 value);
}
'''

# Copy of contract: https://github.com/neonlabsorg/neon-evm/blob/develop/evm_loader/SPL_ERC20_Wrapper.sol
ERC20_CONTRACT_SOURCE = '''
// SPDX-License-Identifier: MIT

pragma solidity >=0.5.12;

/*abstract*/ contract NeonERC20Wrapper /*is IERC20*/ {
    address constant NeonERC20 = 0xff00000000000000000000000000000000000001;

    string public name;
    string public symbol;
    bytes32 public tokenMint;

    constructor(
        string memory _name,
        string memory _symbol,
        bytes32 _tokenMint
    ) {
        name = _name;
        symbol = _symbol;
        tokenMint = _tokenMint;
    }

    fallback() external {
        bytes memory call_data = abi.encodePacked(tokenMint, msg.data);
        (bool success, bytes memory result) = NeonERC20.delegatecall(call_data);

        require(success, string(result));

        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
'''


@logged_group("neon.proxy")
class ERC20Wrapper:
    proxy: Web3
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

    def __init__(self, proxy: Web3,
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
        compiled_interface = compile_source(ERC20_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        compiled_wrapper = compile_source(ERC20_CONTRACT_SOURCE)
        wrapper_id, wrapper_interface = compiled_wrapper.popitem()
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
        txn = Transaction()
        create_txn = spl_token.create_associated_token_account(
            payer=payer.public_key(), owner=owner, mint=self.token.pubkey
        )
        txn.add(create_txn)
        self.token._conn.send_transaction(txn, payer, opts=TxOpts(skip_preflight = True, skip_confirmation=False))
        return create_txn.keys[1].pubkey

    def create_neon_erc20_account_instruction(self, payer: PublicKey, eth_address: str):
        return TransactionInstruction(
            program_id=self.evm_loader_id,
            data=bytes.fromhex('0F'),
            keys=[
                AccountMeta(pubkey=payer, is_signer=True, is_writable=True),
                AccountMeta(pubkey=self.get_neon_erc20_account_address(eth_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.get_neon_account_address(eth_address), is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.solana_contract_address, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.token.pubkey, is_signer=False, is_writable=True),
                AccountMeta(pubkey=SYS_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(pubkey=SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ]
        )

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
