from datetime import datetime
from solana.publickey import PublicKey
from logged_groups import logged_group

from ..common_neon.address import ether2program, getTokenAddr, EthereumAddress
from ..common_neon.solana_interactor import SolanaInteractor
from ..environment import  read_elf_params, TIMEOUT_TO_RELOAD_NEON_CONFIG


@logged_group("neon.Proxy")
def neon_config_load(ethereum_model, *, logger):
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


@logged_group("neon.Proxy")
def get_token_balance_gwei(solana: SolanaInteractor, pda_account: str, *, logger) -> int:
    neon_token_account = getTokenAddr(PublicKey(pda_account))
    return solana.get_token_account_balance(neon_token_account)


@logged_group("neon.Proxy")
def get_token_balance_or_zero(solana: SolanaInteractor, eth_account: EthereumAddress, *, logger) -> int:
    solana_account, nonce = ether2program(eth_account)
    logger.debug(f"Get balance for eth account: {eth_account} aka: {solana_account}")
    return get_token_balance_gwei(solana, solana_account)


def is_account_exists(solana: SolanaInteractor, eth_account: EthereumAddress) -> bool:
    pda_account, nonce = ether2program(eth_account)
    info = solana.get_account_info(pda_account)
    return info is not None

