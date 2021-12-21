# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""

from .proxy import entry_point
import os
from .indexer.airdropper import run_airdropper

if __name__ == '__main__':
    airdropper_mode = os.environ.get('AIRDROPPER_MODE', 'False').lower() in [1, 'true', 'True']
    if airdropper_mode:
        print("Will run in airdropper mode")
        solana_url = os.environ['SOLANA_URL']
        evm_loader_id = os.environ['EVM_LOADER']
        faucet_url = os.environ['FAUCET_URL']
        wrapper_whitelist = os.environ['INDEXER_ERC20_WRAPPER_WHITELIST'].split(',')
        log_level = os.environ['LOG_LEVEL']
        price_update_interval = int(os.environ.get('PRICE_UPDATE_INTERVAL', '60'))
        neon_decimals = int(os.environ.get('NEON_DECIMALS', '9'))
        run_airdropper(solana_url,
                       evm_loader_id,
                       faucet_url,
                       wrapper_whitelist,
                       log_level,
                       price_update_interval,
                       neon_decimals)
    else:
        entry_point()
