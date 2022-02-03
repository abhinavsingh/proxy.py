import os
from web3 import Web3
import unittest
from solana.publickey import PublicKey
from solcx import compile_source, install_solc


proxy_url = os.environ.get('PROXY_URL', 'http://127.0.0.1:9090/solana')
solana_url = os.environ.get("SOLANA_URL", "http://127.0.0.1:8899")
evm_loader_id = PublicKey(os.environ.get("EVM_LOADER"))
ETH_TOKEN_MINT_ID: PublicKey = PublicKey("HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU")

proxy = Web3(Web3.HTTPProvider(proxy_url))
install_solc(version='0.7.0')

INCREAZE_STORAGE_CONTRACT = '''
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

class resize_storage_account(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        print("\n\nhttps://app.zenhub.com/workspaces/solana-evm-6007c75a9dc141001100ccb8/issues/neonlabsorg/proxy-model.py/233")
        self.account = proxy.eth.account.create()
        print('account.address:', self.account.address)

        compiled = compile_source(INCREAZE_STORAGE_CONTRACT)
        id, interface = compiled.popitem()
        contract = proxy.eth.contract(abi=interface['abi'], bytecode=interface['bin'])
        trx = proxy.eth.account.sign_transaction(dict(
            nonce=proxy.eth.get_transaction_count(self.account.address),
            chainId=proxy.eth.chain_id,
            gas=987654321,
            gasPrice=0,
            to='',
            value=0,
            data=contract.bytecode),
            self.account.key
        )
        signature = proxy.eth.send_raw_transaction(trx.rawTransaction)
        receipt = proxy.eth.wait_for_transaction_receipt(signature)

        self.contract = proxy.eth.contract(
            address=receipt.contractAddress,
            abi=contract.abi,
            bytecode=interface['bin']
        )

    def test_01_resize_storage_account(self):
        print("\n\nresize_storage_account")
        nonce = proxy.eth.get_transaction_count(self.account.address)
        tx = self.contract.functions.inc().buildTransaction({'nonce': nonce})
        tx = proxy.eth.account.sign_transaction(tx, self.account.key)
        signature = proxy.eth.send_raw_transaction(tx.rawTransaction)
        receipt = proxy.eth.wait_for_transaction_receipt(signature)
        self.assertIsNotNone(receipt)

    def test_02_get_code_for_resized_storage_account(self):
        print("\n\nget_code_for_resized_storage_account")
        code = proxy.eth.get_code(self.contract.address)
        print("code from proxy: {code.hex()}", code.hex())
        print("code from contract: {self.contract.bytecode.hex()}", self.contract.bytecode.hex())
        self.assertEqual(code, self.contract.bytecode[-len(code):])

if __name__ == '__main__':
    unittest.main()
