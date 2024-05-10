# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from .proxy import Proxy, main, grout, sleep_loop, entry_point
from .testing import TestCase


__all__ = [
    # Grout entry point. See
    # https://jaxl.io/
    'grout',
    # PyPi package entry_point. See
    # https://github.com/abhinavsingh/proxy.py#from-command-line-when-installed-using-pip
    'entry_point',
    # Embed proxy.py. See
    # https://github.com/abhinavsingh/proxy.py#embed-proxypy
    'main',
    # Unit testing with proxy.py. See
    # https://github.com/abhinavsingh/proxy.py#unit-testing-with-proxypy
    'TestCase',
    'Proxy',
    # Utility exposed for demos
    'sleep_loop',
]
