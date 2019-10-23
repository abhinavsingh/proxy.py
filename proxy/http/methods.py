# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import NamedTuple


HttpMethods = NamedTuple('HttpMethods', [
    ('GET', bytes),
    ('HEAD', bytes),
    ('POST', bytes),
    ('PUT', bytes),
    ('DELETE', bytes),
    ('CONNECT', bytes),
    ('OPTIONS', bytes),
    ('TRACE', bytes),
    ('PATCH', bytes),
])
httpMethods = HttpMethods(
    b'GET',
    b'HEAD',
    b'POST',
    b'PUT',
    b'DELETE',
    b'CONNECT',
    b'OPTIONS',
    b'TRACE',
    b'PATCH',
)
