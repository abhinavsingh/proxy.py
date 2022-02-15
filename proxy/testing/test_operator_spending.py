import os, subprocess, unittest
from web3 import Web3
from solana.publickey import PublicKey
from solcx import compile_source
from solana.rpc.api import Client
from solana.rpc.commitment import Confirmed
from solana_utils import *

from proxy.testing.testing_helpers import request_airdrop

proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
evm_loader_id = PublicKey(os.environ.get("EVM_LOADER"))
# evm_loader_id = PublicKey("qRuSs83NqmYLuUtF1WRcJ6cffqgMcusi8kr3Efchv7h")
neon_cli_timeout = float(os.environ.get("NEON_CLI_TIMEOUT", "0.1"))

proxy = Web3(Web3.HTTPProvider(proxy_url))

CONTRACT = '''
pragma solidity >=0.5.12;
contract Increase_storage {
    mapping(address => mapping(uint256 => uint256)) data;
    uint256 count = 0;
    constructor(){
        inc();
    }
    function inc() public {
        uint256 n = count +  32;
        while (count < n){
            data[msg.sender][count] = uint256(count);
            count = count + 1;
        }
    }
}
'''

class neon_cli:
    def call(self, *args):
        try:
            cmd = ["neon-cli",
                   "--commitment=recent",
                   "--url", solana_url,
                   "--evm_loader={}".format(evm_loader_id),
                   ] + list(args)
            print(cmd)
            return subprocess.check_output(cmd, timeout=neon_cli_timeout, universal_newlines=True)
        except subprocess.CalledProcessError as err:
            import sys
            print("ERR: neon-cli error {}".format(err))
            raise

class transacton_cost(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        print("\n\nhttps://app.zenhub.com/workspaces/solana-evm-6007c75a9dc141001100ccb8/issues/neonlabsorg/proxy-model.py/245")
        self.account = proxy.eth.account.create()
        print('account.address:', self.account.address)
        request_airdrop(self.account.address)

        self.client = Client(solana_url)
        wallet = WalletAccount(wallet_path())
        self.acc = wallet.get_acc()

    @unittest.skip("only for debug")
    def test_deploy_cost(self):
        print("\n\ntest_deploy_cost")

        compiled = compile_source(CONTRACT)
        id, interface = compiled.popitem()
        contract = proxy.eth.contract(abi=interface['abi'], bytecode=interface['bin'])
        trx = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(self.account.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=1000000000,
            to='',
            value=0,
            data=contract.bytecode),
            self.account.key
        )
        print("trx_hash", trx.hash.hex()[2:])

        balance_pre = int(self.client.get_balance(self.acc.public_key(), commitment=Confirmed)['result']['value'])
        print("incoming balance  {:,}".format(balance_pre).replace(',',' '))

        signature = proxy.eth.send_raw_transaction(trx.rawTransaction)
        receipt = proxy.eth.wait_for_transaction_receipt(signature)
        # self.contract = proxy.eth.contract(
        #     address=receipt.contractAddress,
        #     abi=contract.abi
        # )

        balance_post = int(self.client.get_balance(self.acc.public_key(), commitment=Confirmed)['result']['value'])
        print("outgoing  balance {:,}".format(balance_post).replace(',', ' '))
        print("cost {:,}".format(balance_pre-balance_post).replace(',', ' '))




