# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import NamedTuple

EventNames = NamedTuple('EventNames', [
    ('SUBSCRIBE', int),
    ('UNSUBSCRIBE', int),
    ('WORK_STARTED', int),
    ('WORK_FINISHED', int),
    ('REQUEST_COMPLETE', int),
    ('RESPONSE_HEADERS_COMPLETE', int),
    ('RESPONSE_CHUNK_RECEIVED', int),
    ('RESPONSE_COMPLETE', int),
])
eventNames = EventNames(1, 2, 3, 4, 5, 6, 7, 8)
