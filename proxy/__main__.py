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
from .indexer.indexer import run_indexer


if __name__ == '__main__':
    solana_url = os.environ['SOLANA_URL']
    evm_loader_id = os.environ['EVM_LOADER']
    print(f"Will run with SOLANA_URL={solana_url}; EVM_LOADER={evm_loader_id}")

    indexer_mode = os.environ.get('INDEXER_MODE', 'False').lower() in [1, 'true', 'True']

    if indexer_mode:
        print("Will run in indexer mode")
        run_indexer(solana_url)
    else:
        from .statistics_exporter.prometheus_proxy_server import PrometheusProxyServer
        PrometheusProxyServer()

        print("Will run in proxy mode")
        entry_point()
