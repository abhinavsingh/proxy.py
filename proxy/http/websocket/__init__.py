# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       http
       Submodules
       websocket
       Websocket
"""
from .client import WebsocketClient
from .frame import WebsocketFrame, websocketOpcodes


__all__ = [
    'websocketOpcodes',
    'WebsocketFrame',
    'WebsocketClient',
]
