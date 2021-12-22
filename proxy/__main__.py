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
from solana.rpc.api import Client

if __name__ == '__main__':
    airdropper_mode = os.environ.get('AIRDROPPER_MODE', 'False').lower() in [1, 'true', 'True']
    if airdropper_mode:
        print("Will run in airdropper mode")
        solana_url = os.environ['SOLANA_URL']
        evm_loader_id = os.environ['EVM_LOADER']
        faucet_url = os.environ['FAUCET_URL']
        wrapper_whitelist = os.environ['INDEXER_ERC20_WRAPPER_WHITELIST']
        if wrapper_whitelist != 'ANY':
            wrapper_whitelist = wrapper_whitelist.split(',')
        log_level = os.environ['LOG_LEVEL']
        price_update_interval = int(os.environ.get('PRICE_UPDATE_INTERVAL', '60'))
        neon_decimals = int(os.environ.get('NEON_DECIMALS', '9'))

        start_slot = os.environ.get('START_SLOT', None)
        if start_slot == 'LATEST':
            client = Client(solana_url)
            start_slot = client.get_slot(commitment="confirmed")["result"]
        if start_slot is None: # by default
            start_slot = 0
        else: # try to convert into integer
            start_slot = int(start_slot)

        run_airdropper(solana_url,
                       evm_loader_id,
                       faucet_url,
                       wrapper_whitelist,
                       log_level,
                       price_update_interval,
                       neon_decimals,
                       start_slot)
    else:
        entry_point()
