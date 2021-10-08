## File: test_erc20_wrapper_contract.py
## Integration test for the Neon ERC20 Wrapper contract.

from time import sleep
import unittest
import os
from solana.rpc.commitment import Confirmed, Recent
from solana.rpc.types import TxOpts
from web3 import Web3
from solcx import install_solc
from spl.token.client import Token as SplToken
from spl.token.constants import TOKEN_PROGRAM_ID
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from proxy.plugin.solana_rest_api_tools import createERC20TokenAccountTrx, createEtherAccountTrx

# install_solc(version='latest')
install_solc(version='0.7.6')
from solcx import compile_source

EXTRA_GAS = int(os.environ.get("EXTRA_GAS", "100000"))
proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
evm_loader_id = PublicKey(os.environ.get("EVM_LOADER"))
proxy = Web3(Web3.HTTPProvider(proxy_url))
admin = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/admin')
user = proxy.eth.account.create('issues/neonlabsorg/proxy-model.py/197/user')
proxy.eth.default_account = admin.address

NAME = 'NEON'
SYMBOL = 'NEO'

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
}
'''

# Copy of contract: https://github.com/neonlabsorg/neon-evm/blob/develop/evm_loader/SPL_ERC20_Wrapper.sol
ERC20_WRAPPER_SOURCE = '''
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

class Test_erc20_wrapper_contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/197")
        print('admin.key:', admin.key.hex())
        print('admin.address:', admin.address)
        print('user.key:', user.key.hex())
        print('user.address:', user.address)

        cls.create_token_mint(cls)
        cls.deploy_erc20_wrapper_contract(cls)
        cls.create_token_accounts(cls)


    def create_token_mint(self):
        self.solana_client = SolanaClient(solana_url)

        self.solana_account = SolanaAccount()
        self.solana_client.request_airdrop(self.solana_account.public_key(), 1000_000_000_000, Confirmed)

        while True:
            balance = self.solana_client.get_balance(self.solana_account.public_key(), Confirmed)["result"]["value"]
            if balance > 0:
                break
            sleep(1)

        self.token = SplToken.create_mint(
            self.solana_client,
            self.solana_account,
            self.solana_account.public_key(),
            9,
            TOKEN_PROGRAM_ID,
        )

    def deploy_erc20_wrapper_contract(self):
        compiled_interface = compile_source(ERC20_INTERFACE_SOURCE)
        interface_id, interface = compiled_interface.popitem()
        self.interface = interface

        compiled_wrapper = compile_source(ERC20_WRAPPER_SOURCE)
        wrapper_id, wrapper_interface = compiled_wrapper.popitem()
        self.wrapper = wrapper_interface
        
        erc20 = proxy.eth.contract(abi=self.wrapper['abi'], bytecode=wrapper_interface['bin'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx_constructor = erc20.constructor(NAME, SYMBOL, bytes(self.token.pubkey)).buildTransaction(tx)
        tx_deploy = proxy.eth.account.sign_transaction(tx_constructor, admin.key)
        #print('tx_deploy:', tx_deploy)
        tx_deploy_hash = proxy.eth.send_raw_transaction(tx_deploy.rawTransaction)
        print('tx_deploy_hash:', tx_deploy_hash.hex())
        tx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(tx_deploy_hash)
        print('tx_deploy_receipt:', tx_deploy_receipt)
        print('deploy status:', tx_deploy_receipt.status)
        self.contract_address = tx_deploy_receipt.contractAddress

    def create_token_accounts(self):
        contract_address_bytes = bytes.fromhex(self.contract_address[2:])
        contract_address_solana = PublicKey.find_program_address([b"\1", contract_address_bytes], evm_loader_id)[0]

        admin_address_bytes = bytes.fromhex(admin.address[2:])
        admin_address_solana = PublicKey.find_program_address([b"\1", admin_address_bytes], evm_loader_id)[0]

        admin_token_seeds = [ b"\1", b"ERC20Balance", bytes(self.token.pubkey), contract_address_bytes, admin_address_bytes ]
        admin_token_key = PublicKey.find_program_address(admin_token_seeds, evm_loader_id)[0]
        admin_token_info = { "key": admin_token_key, "owner": admin_address_solana, "contract": contract_address_solana, "mint": self.token.pubkey }
        self.solana_client.send_transaction(createERC20TokenAccountTrx(self.solana_account, admin_token_info), self.solana_account, opts=TxOpts(skip_preflight=True, skip_confirmation=False))
        self.token.mint_to(admin_token_key, self.solana_account, 10_000_000_000_000, opts=TxOpts(skip_preflight=True, skip_confirmation=False))

    def test_erc20_name(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.wrapper['abi'])
        name = erc20.functions.name().call()
        self.assertEqual(name, NAME)

    def test_erc20_symbol(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.wrapper['abi'])
        sym = erc20.functions.symbol().call()
        self.assertEqual(sym, SYMBOL)

    def test_erc20_decimals(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.interface['abi'])
        decs = erc20.functions.decimals().call()
        self.assertEqual(decs, 9)

    def test_erc20_totalSupply(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.interface['abi'])
        ts = erc20.functions.totalSupply().call()
        self.assertGreater(ts, 0)

    def test_erc20_balanceOf(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.interface['abi'])
        b = erc20.functions.balanceOf(admin.address).call()
        self.assertGreater(b, 0)
        b = erc20.functions.balanceOf(user.address).call()
        self.assertEqual(b, 0)

    def test_erc20_transfer(self):
        erc20 = proxy.eth.contract(address=self.contract_address, abi=self.interface['abi'])
        nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
        tx = {'nonce': nonce}
        tx = erc20.functions.transfer(user.address, 1000).buildTransaction(tx)
        tx = proxy.eth.account.sign_transaction(tx, admin.key)
        tx_hash = proxy.eth.send_raw_transaction(tx.rawTransaction)
        print('tx_hash:',tx_hash)
        tx_receipt = proxy.eth.wait_for_transaction_receipt(tx_hash)
        self.assertIsNotNone(tx_receipt)

if __name__ == '__main__':
    unittest.main()
