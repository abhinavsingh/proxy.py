import base64
import logging

from datetime import datetime
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey
from solana.rpc.api import Client as SolanaClient
from solana.rpc.commitment import Confirmed

from ..common_neon.address import ether2program, getTokenAddr, EthereumAddress, AccountInfo
from ..common_neon.errors import SolanaAccountNotFoundError, SolanaErrors
from ..common_neon.layouts import ACCOUNT_INFO_LAYOUT
from ..common_neon.neon_instruction import NeonInstruction
from ..common_neon.solana_interactor import SolanaInteractor
from ..common_neon.transaction_sender import TransactionSender
from ..common_neon.emulator_interactor import call_emulated
from ..common_neon.utils import get_from_dict
from ..environment import NEW_USER_AIRDROP_AMOUNT, read_elf_params, TIMEOUT_TO_RELOAD_NEON_CONFIG, EXTRA_GAS


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def neon_config_load(ethereum_model):
    try:
        ethereum_model.neon_config_dict
    except AttributeError:
        logger.debug("loading the neon config dict for the first time!")
        ethereum_model.neon_config_dict = dict()
    else:
        elapsed_time = datetime.now().timestamp() - ethereum_model.neon_config_dict['load_time']
        logger.debug('elapsed_time={} proxy_id={}'.format(elapsed_time, ethereum_model.proxy_id))
        if elapsed_time < TIMEOUT_TO_RELOAD_NEON_CONFIG:
            return

    read_elf_params(ethereum_model.neon_config_dict)
    ethereum_model.neon_config_dict['load_time'] = datetime.now().timestamp()
    # 'Neon/v0.3.0-rc0-d1e4ff618457ea9cbc82b38d2d927e8a62168bec
    ethereum_model.neon_config_dict['web3_clientVersion'] = 'Neon/v' + \
                                                            ethereum_model.neon_config_dict['NEON_PKG_VERSION'] + \
                                                            '-' \
                                                            + ethereum_model.neon_config_dict['NEON_REVISION']
    logger.debug(ethereum_model.neon_config_dict)


def call_signed(signer, client, eth_trx, steps):
    solana_interactor = SolanaInteractor(signer, client)
    trx_sender = TransactionSender(solana_interactor, eth_trx, steps)
    return trx_sender.execute()



def _getAccountData(client, account, expected_length, owner=None):
    info = client.get_account_info(account, commitment=Confirmed)['result']['value']
    if info is None:
        raise Exception("Can't get information about {}".format(account))

    data = base64.b64decode(info['data'][0])
    if len(data) < expected_length:
        raise Exception("Wrong data length for account data {}".format(account))
    return data


def getAccountInfo(client, eth_account: EthereumAddress):
    account_sol, nonce = ether2program(eth_account)
    info = _getAccountData(client, account_sol, ACCOUNT_INFO_LAYOUT.sizeof())
    return AccountInfo.frombytes(info)


def create_eth_account_and_airdrop(client: SolanaClient, signer: SolanaAccount, eth_account: EthereumAddress):
    trx = NeonInstruction(signer.public_key()).make_trx_with_create_and_airdrop (eth_account)
    result = SolanaInteractor(signer, client).send_transaction(trx, None, reason='create_eth_account_and_airdrop')
    error = result.get("error")
    if error is not None:
        logger.error(f"Failed to create eth_account and airdrop: {eth_account}, error occurred: {error}")
        raise Exception("Create eth_account error")


def get_token_balance_gwei(client: SolanaClient, pda_account: str) -> int:
    neon_token_account = getTokenAddr(PublicKey(pda_account))
    rpc_response = client.get_token_account_balance(neon_token_account, commitment=Confirmed)
    error = rpc_response.get('error')
    if error is not None:
        message = error.get("message")
        if message == SolanaErrors.AccountNotFound.value:
            raise SolanaAccountNotFoundError()
        logger.error(f"Failed to get_token_balance_gwei by neon_token_account: {neon_token_account}, "
                     f"got get_token_account_balance error: \"{message}\"")
        raise Exception("Getting balance error")

    balance = get_from_dict(rpc_response, "result", "value", "amount")
    if balance is None:
        logger.error(f"Failed to get_token_balance_gwei by neon_token_account: {neon_token_account}, response: {rpc_response}")
        raise Exception("Unexpected get_balance response")
    return int(balance)


def get_token_balance_or_airdrop(client: SolanaClient, signer: SolanaAccount, eth_account: EthereumAddress) -> int:
    solana_account, nonce = ether2program(eth_account)
    logger.debug(f"Get balance for eth account: {eth_account} aka: {solana_account}")

    try:
        return get_token_balance_gwei(client, solana_account)
    except SolanaAccountNotFoundError:
        logger.debug(f"Account not found:  {eth_account} aka: {solana_account} - create")
        if NEW_USER_AIRDROP_AMOUNT == 0:
            return 0
            
        create_eth_account_and_airdrop(client, signer, eth_account)
        return get_token_balance_gwei(client, solana_account)


def is_account_exists(client: SolanaClient, eth_account: EthereumAddress) -> bool:
    pda_account, nonce = ether2program(eth_account)
    info = client.get_account_info(pda_account, commitment=Confirmed)
    value = get_from_dict(info, "result", "value")
    return value is not None


def estimate_gas(client: SolanaClient, signer: SolanaAccount, contract_id: str, caller_eth_account: EthereumAddress,
                 data: str = None, value: str = None):
    if not is_account_exists(client, caller_eth_account):
        create_eth_account_and_airdrop(client, signer, caller_eth_account)
    result = call_emulated(contract_id, str(caller_eth_account), data, value)
    used_gas = result.get("used_gas")
    if used_gas is None:
        logger.error(f"Failed estimate_gas, unexpected result, by contract_id: {contract_id}, caller_eth_account: "
                     f"{caller_eth_account}, data: {data}, value: {value}, emulation result: {result}")
        raise Exception("Bad estimate_gas result")
    return used_gas + EXTRA_GAS
