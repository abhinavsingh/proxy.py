# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import proxy


def entry_point() -> None:
    with proxy.Proxy(
            enable_web_server=True,
            port=9000,
            # NOTE: Pass plugins via *args if you define custom flags.
            # Currently plugins passed via **kwargs are not discovered for
            # custom flags by proxy.py
            #
            # See https://github.com/abhinavsingh/proxy.py/issues/871
            plugins=[
                'app.plugins.MyWebServerPlugin',
                'app.plugins.MyProxyPlugin',
            ]
    ) as _:
        proxy.sleep_loop()
