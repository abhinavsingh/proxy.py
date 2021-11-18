# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
"""
    .. spelling::

       http
       iterable
"""
from typing import NamedTuple


HttpParserStates = NamedTuple(
    'HttpParserStates', [
        ('INITIALIZED', int),
        ('LINE_RCVD', int),
        ('RCVING_HEADERS', int),
        ('HEADERS_COMPLETE', int),
        ('RCVING_BODY', int),
        ('COMPLETE', int),
    ],
)
httpParserStates = HttpParserStates(1, 2, 3, 4, 5, 6)

HttpParserTypes = NamedTuple(
    'HttpParserTypes', [
        ('REQUEST_PARSER', int),
        ('RESPONSE_PARSER', int),
    ],
)
httpParserTypes = HttpParserTypes(1, 2)
