#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1001,"jsonrpc":"2.0","params":[]}' $PROXY_URL

echo ''
echo 'Test: Base Eth API'
python3 -c "
import os
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
from web3 import Web3
proxy = Web3(Web3.HTTPProvider(proxy_url))
print('default_block:', proxy.eth.default_block)
print('chain_id:', proxy.eth.chain_id)
block_number = proxy.eth.block_number
print('block_number:', block_number)
block = proxy.eth.get_block(block_number)
print('block:', block)
transaction_hash = block.transactions[0].hex()
print('transaction_hash:', transaction_hash)
#transaction = proxy.eth.get_transaction(transaction_hash)
#transaction = proxy.eth.get_transaction('0xd387efb40347ff662f29387e17e8a5f5d6b22d8e56845a0096490f08903a8248')
#print('transaction:', transaction)
#block_transaction_count = proxy.eth.get_block_transaction_count(block_number)
#print('block_transaction_count:', block_transaction_count)
#print('balance:', proxy.eth.get_balance('0xd3CdA913deB6f67967B99D67aCDFa1712C293601'))
#code = proxy.eth.get_code('0x6C8f2A135f6ed072DE4503Bd7C4999a1a17F824B', block_number)
#print('code:', code)
"

echo ''
echo 'Test: compile solidity contract "Storage", deploy it, and call "store(147)" with right and bad nonce'
python3 -c "
import os
proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
from web3 import Web3
proxy = Web3(Web3.HTTPProvider(proxy_url))
acc=proxy.eth.account.create('https://github.com/neonlabsorg/proxy-model.py/issues/147')
print(acc.address)
print(acc.privateKey.hex())
proxy.eth.default_account=acc.address

from solcx import install_solc
#install_solc(version='latest')
install_solc(version='0.7.0')
from solcx import compile_source
compiled_sol = compile_source(
'''
pragma solidity >=0.7.0 <0.9.0;
/**
 * @title Storage
 * @dev Store & retrieve value in a variable
 */
contract Storage {
    uint256 number;
    /**
     * @dev Store value in variable
     * @param num value to store
     */
    function store(uint256 num) public {
        number = num;
    }
    /**
     * @dev Return value
     * @return value of 'number'
     */
    function retrieve() public view returns (uint256){
        return number;
    }
}
'''
)
contract_id, contract_interface = compiled_sol.popitem()

storage=proxy.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
trx_deploy = proxy.eth.account.sign_transaction(dict(
    nonce=proxy.eth.get_transaction_count(proxy.eth.default_account),
    chainId=proxy.eth.chain_id,
    gas=987654321,
    gasPrice=0,
    to='',
    value=0,
    data=storage.bytecode),
  acc.privateKey
  )
print('trx_deploy:', trx_deploy)
trx_deploy_hash = proxy.eth.send_raw_transaction(trx_deploy.rawTransaction)
print('trx_deploy_hash:', trx_deploy_hash.hex())
trx_deploy_receipt = proxy.eth.wait_for_transaction_receipt(trx_deploy_hash)
print('trx_deploy_receipt:', trx_deploy_receipt)

storage_contract = proxy.eth.contract(
  address=trx_deploy_receipt.contractAddress,
	abi=storage.abi
)

storage_contract.functions.retrieve().call()
n = storage_contract.functions.retrieve().call()
print('n:', n)
assert n == 0

right_nonce = proxy.eth.get_transaction_count(proxy.eth.default_account)
trx_store = storage_contract.functions.store(147).buildTransaction({'nonce': right_nonce, 'value':741147})
print('trx_store:', trx_store)
trx_store_signed = proxy.eth.account.sign_transaction(trx_store, acc.privateKey)
print('trx_store_signed:', trx_store_signed)
trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
print('trx_store_hash:', trx_store_hash.hex())
trx_store_receipt = proxy.eth.wait_for_transaction_receipt(trx_store_hash)
print('trx_store_receipt:', trx_store_receipt)
n = storage_contract.functions.retrieve().call()
print('n:', n)
assert n == 147

bad_nonce = 1+proxy.eth.get_transaction_count(proxy.eth.default_account)
trx_store = storage_contract.functions.store(147).buildTransaction({'nonce': bad_nonce, 'value':741147})
print('trx_store:', trx_store)
trx_store_signed = proxy.eth.account.sign_transaction(trx_store, acc.privateKey)
print('trx_store_signed:', trx_store_signed)
try:
    trx_store_hash = proxy.eth.send_raw_transaction(trx_store_signed.rawTransaction)
except Exception as e:
    print('type(e):', type(e))
    print('e:', e)
    import json
    response = json.loads(str(e).replace('\'','\"').replace('None','null'))
    print('response:', response)
    print('code:', response['code'])
    assert response['code'] == -32002
    substring_err_147 = 'Invalid Ethereum transaction nonce:'
    print('substring_err_147:', substring_err_147)
    logs = response['data']['logs']
    print('logs:', logs)
    log = [s for s in logs if substring_err_147 in s][0]
    print(log)
    assert len(log) > len(substring_err_147)
    file_name = 'src/entrypoint.rs'
    assert file_name in log
"

echo ''
echo 'Test: Check error response on "Invalid Ethereum transaction nonce" while deploying a contract'
echo 'https://github.com/neonlabsorg/proxy-model.py/issues/147'
RESPONSE=$(curl --header 'Content-Type: application/json' --data '{"id":147001,"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf90134018082dd128080b8e6608060405234801561001057600080fd5b5060c78061001f6000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d146053575b600080fd5b603d607e565b6040518082815260200191505060405180910390f35b607c60048036036020811015606757600080fd5b81019080803590602001909291905050506087565b005b60008054905090565b806000819055505056fea26469706673582212203bc553a7e9b00c07167cc430edb1823d78733185b3335c72c84520889643130364736f6c63430007000033820102a03fd407e0b9dfa921e22415c52228309a4a552a3e725727b021e82c3d86944ccfa07a4cd28d7393cfc48c2dc87b4ed6271f3114889f541200b3673d8e2edc0e4d69"]}' $PROXY_URL)
python3 -c "
import sys
arg=sys.argv[1]
print(arg)
import json
response = json.loads(arg)
print('error:', response['error'])
print('code:', response['error']['code'])
assert response['error']['code'] == -32002
substring = 'Invalid Ethereum transaction nonce:'
print('substring:', substring)
logs = response['error']['data']['logs']
print('logs:', logs)
log = [e for e in logs if substring in e][0]
print('log', log)
assert len(log) > len(substring)
file_name = 'src/entrypoint.rs'
print('file_name', file_name)
assert file_name in log
" "$RESPONSE"

echo ''
echo 'Test: Check eth_estimateGas on deploying a contract'
echo 'https://github.com/neonlabsorg/proxy-model.py/issues/122'
RESPONSE=$(curl -v --header "Content-Type: application/json" --data '{"method":"eth_estimateGas","id":1002,"jsonrpc":"2.0","params":[{"from":"0x55864414d401c9ff160043c50f6daca3bd22ccfc", "value": "0x0", "data":"0x60806040526040518060400160405280600c81526020017f48656c6c6f20576f726c642100000000000000000000000000000000000000008152506000908051906020019061004f929190610062565b5034801561005c57600080fd5b50610107565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100a357805160ff19168380011785556100d1565b828001600101855582156100d1579182015b828111156100d05782518255916020019190600101906100b5565b5b5090506100de91906100e2565b5090565b61010491905b808211156101005760008160009055506001016100e8565b5090565b90565b6102b6806101166000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80631f1bd6921461003b5780633917b3df146100be575b600080fd5b610043610141565b6040518080602001828103825283818151815260200191508051906020019080838360005b83811015610083578082015181840152602081019050610068565b50505050905090810190601f1680156100b05780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6100c66101df565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156101065780820151818401526020810190506100eb565b50505050905090810190601f1680156101335780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156101d75780601f106101ac576101008083540402835291602001916101d7565b820191906000526020600020905b8154815290600101906020018083116101ba57829003601f168201915b505050505081565b606060008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156102775780601f1061024c57610100808354040283529160200191610277565b820191906000526020600020905b81548152906001019060200180831161025a57829003601f168201915b505050505090509056fea265627a7a7231582024368df40ce2133f972294ddde9f574e801391af7268266abe1646f640b2294c64736f6c63430005110032"}]}' $PROXY_URL)
python3 -c "
import sys
arg=sys.argv[1]
print(arg)
import json
resp = json.loads(arg)
print('used_gas:', resp['result'])
assert resp['result'] == 89078
" "$RESPONSE"

echo ''
echo 'Test: Check eth_estimateGas on deploying a contract with the empty value'
echo 'https://github.com/neonlabsorg/proxy-model.py/issues/122'
RESPONSE=$(curl -v --header "Content-Type: application/json" --data '{"method":"eth_estimateGas","id":1002,"jsonrpc":"2.0","params":[{"from":"0x55864414d401c9ff160043c50f6daca3bd22ccfc", "data":"0x60806040526040518060400160405280600c81526020017f48656c6c6f20576f726c642100000000000000000000000000000000000000008152506000908051906020019061004f929190610062565b5034801561005c57600080fd5b50610107565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100a357805160ff19168380011785556100d1565b828001600101855582156100d1579182015b828111156100d05782518255916020019190600101906100b5565b5b5090506100de91906100e2565b5090565b61010491905b808211156101005760008160009055506001016100e8565b5090565b90565b6102b6806101166000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c80631f1bd6921461003b5780633917b3df146100be575b600080fd5b610043610141565b6040518080602001828103825283818151815260200191508051906020019080838360005b83811015610083578082015181840152602081019050610068565b50505050905090810190601f1680156100b05780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b6100c66101df565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156101065780820151818401526020810190506100eb565b50505050905090810190601f1680156101335780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156101d75780601f106101ac576101008083540402835291602001916101d7565b820191906000526020600020905b8154815290600101906020018083116101ba57829003601f168201915b505050505081565b606060008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156102775780601f1061024c57610100808354040283529160200191610277565b820191906000526020600020905b81548152906001019060200180831161025a57829003601f168201915b505050505090509056fea265627a7a7231582024368df40ce2133f972294ddde9f574e801391af7268266abe1646f640b2294c64736f6c63430005110032"}]}' $PROXY_URL)
python3 -c "
import sys
arg=sys.argv[1]
print(arg)
import json
resp = json.loads(arg)
print('used_gas:', resp['result'])
assert resp['result'] == 89078
" "$RESPONSE"

echo ''
echo 'Test: Check eth_estimateGas on deploying a contract with the empty data'
echo 'https://github.com/neonlabsorg/proxy-model.py/issues/122'
RESPONSE=$(curl -v --header "Content-Type: application/json" --data '{"method":"eth_estimateGas","id":1002,"jsonrpc":"2.0","params":[{"from":"0x55864414d401c9ff160043c50f6daca3bd22ccfc", "value": "0x0"}]}' $PROXY_URL)
python3 -c "
import sys
arg=sys.argv[1]
print(arg)
import json
resp = json.loads(arg)
print('used_gas:', resp['result'])
assert resp['result'] == 53001
" "$RESPONSE"

echo ''
echo 'Test: Check eth_estimateGas on deploying a contract with the empty data and value'
echo 'https://github.com/neonlabsorg/proxy-model.py/issues/122'
RESPONSE=$(curl -v --header "Content-Type: application/json" --data '{"method":"eth_estimateGas","id":1002,"jsonrpc":"2.0","params":[{"from":"0x55864414d401c9ff160043c50f6daca3bd22ccfc"}]}' $PROXY_URL)
python3 -c "
import sys
arg=sys.argv[1]
print(arg)
import json
resp = json.loads(arg)
print('used_gas:', resp['result'])
assert resp['result'] == 53001
" "$RESPONSE"

echo "Deploy test success"
exit 0
