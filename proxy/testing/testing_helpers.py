import dataclasses
import os
import requests
import solcx
from eth_account.account import LocalAccount
from web3 import Web3, eth as web3_eth
import eth_utils
from typing import Union, Type, Any, Dict


@dataclasses.dataclass
class ContractCompiledInfo:
    contract_interface: Dict
    contract: web3_eth.Contract


class SolidityContractDeployer:

    _CONTRACT_TYPE = Union[Type[web3_eth.Contract], web3_eth.Contract]

    def __init__(self):
        proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
        self._web3 = Web3(Web3.HTTPProvider(proxy_url))

    def compile_contract(self, solidity_source_code: str) -> ContractCompiledInfo:
        """Returns tuple of """
        compile_result = solcx.compile_source(solidity_source_code)
        _, contract_interface = compile_result.popitem()
        contract = self._web3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
        return ContractCompiledInfo(contract_interface, contract)

    def compile_and_deploy_contract(self, contract_owner: LocalAccount, solidity_source_code: str) -> _CONTRACT_TYPE:
        compiled_info = self.compile_contract(solidity_source_code)
        contract = compiled_info.contract
        nonce = self._web3.eth.get_transaction_count(contract_owner.address)
        chain_id = self._web3.eth.chain_id
        minimal_gas_price = int(os.environ.get("MINIMAL_GAS_PRICE", 1)) * eth_utils.denoms.gwei
        trx_signed = self._web3.eth.account.sign_transaction(
            dict(nonce=nonce, chainId=chain_id, gas=987654321, gasPrice=minimal_gas_price, to='', value=0, data=contract.bytecode),
            contract_owner.key)
        trx_hash = self._web3.eth.send_raw_transaction(trx_signed.rawTransaction)
        trx_receipt = self._web3.eth.wait_for_transaction_receipt(trx_hash)
        contract = self._web3.eth.contract(address=trx_receipt.contractAddress, abi=contract.abi)
        return contract

    @property
    def web3(self) -> Web3:
        return self._web3


def request_airdrop(address, amount: int = 10):
    FAUCET_URL = os.environ.get('FAUCET_URL', 'http://faucet:3333')
    url = FAUCET_URL + '/request_neon'
    data = f'{{"wallet": "{address}", "amount": {amount}}}'
    r = requests.post(url, data=data)
    if not r.ok:
        print()
        print('Bad response:', r)
    assert(r.ok)
