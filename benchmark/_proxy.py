# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import ipaddress

import proxy


if __name__ == '__main__':
    with proxy.Proxy(
            ['--plugin', 'proxy.plugin.WebServerPlugin'],
            hostname=ipaddress.ip_address('127.0.0.1'),
            port=8899,
            backlog=65536,
            open_file_limit=65536,
            enable_web_server=True,
            disable_proxy_server=False,
            num_acceptors=10,
            local_executor=1,
            log_file='/dev/null',
    ) as _:
        while True:
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                break
