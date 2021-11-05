# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       Submodules
       websocket
       Websocket
"""
from .dashboard import ProxyDashboard
from .inspect_traffic import InspectTrafficPlugin
from .plugin import ProxyDashboardWebsocketPlugin


__all__ = [
    'ProxyDashboard',
    'InspectTrafficPlugin',
    'ProxyDashboardWebsocketPlugin',
]
