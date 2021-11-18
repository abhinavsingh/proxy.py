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

       eventing
       iterable
"""
from typing import NamedTuple

# Name of the events that eventing framework supports.
#
# Ideally this must be configurable via command line or
# at-least extendable via plugins.
EventNames = NamedTuple(
    'EventNames', [
        ('SUBSCRIBE', int),
        ('SUBSCRIBED', int),
        ('UNSUBSCRIBE', int),
        ('UNSUBSCRIBED', int),
        ('DISPATCHER_SHUTDOWN', int),
        ('WORK_STARTED', int),
        ('WORK_FINISHED', int),
        ('REQUEST_COMPLETE', int),
        ('RESPONSE_HEADERS_COMPLETE', int),
        ('RESPONSE_CHUNK_RECEIVED', int),
        ('RESPONSE_COMPLETE', int),
    ],
)
eventNames = EventNames(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
