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
        airdrop_amount = int(os.environ['AIRDROP_AMOUNT'])
        log_level = os.environ['LOG_LEVEL']
        run_airdropper(solana_url,
                       evm_loader_id,
                       faucet_url,
                       wrapper_whitelist,
                       airdrop_amount,
                       log_level)
    else:
        entry_point()
