# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from .proxy import entry_point, main, Proxy
from .testing import TestCase
from .dashboard import ProxyDashboard

__all__ = [
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
    # This is here to make sure --enable-dashboard
    # flag is discoverable by automagically.
    #
    # Because, ProxyDashboard is not imported anywhere,
    # without this patch, users will have to explicitly
    # enable proxy.dashboard.ProxyDashboard plugin
    # to use --enable-dashboard flag.
    'ProxyDashboard',
]
