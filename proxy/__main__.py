# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""

from solana.publickey import PublicKey
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
        pyth_mapping_account = PublicKey(os.environ['PYTH_MAPPING_ACCOUNT'])
        faucet_url = os.environ['FAUCET_URL']
        wrapper_whitelist = os.environ['INDEXER_ERC20_WRAPPER_WHITELIST']
        if wrapper_whitelist != 'ANY':
            wrapper_whitelist = wrapper_whitelist.split(',')
        log_level = os.environ['LOG_LEVEL']
        neon_decimals = int(os.environ.get('NEON_DECIMALS', '9'))

        start_slot = os.environ.get('START_SLOT', 0)
        pp_solana_url = os.environ.get('PP_SOLANA_URL', None)
        max_conf = float(os.environ.get('MAX_CONFIDENCE_INTERVAL', 0.02))

        run_airdropper(solana_url,
                       evm_loader_id,
                       pyth_mapping_account,
                       faucet_url,
                       wrapper_whitelist,
                       log_level,
                       neon_decimals,
                       start_slot,
                       pp_solana_url,
                       max_conf)
    else:
        entry_point()
