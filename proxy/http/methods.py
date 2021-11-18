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


# Ref: https://www.iana.org/assignments/http-methods/http-methods.xhtml
HttpMethods = NamedTuple(
    'HttpMethods', [
        ('ACL', bytes),
        ('BASELINE_CONTROL', bytes),
        ('BIND', bytes),
        ('CHECKIN', bytes),
        ('CHECKOUT', bytes),
        ('CONNECT', bytes),
        ('COPY', bytes),
        ('DELETE', bytes),
        ('GET', bytes),
        ('HEAD', bytes),
        ('LABEL', bytes),
        ('LINK', bytes),
        ('LOCK', bytes),
        ('MERGE', bytes),
        ('MKACTIVITY', bytes),
        ('MKCALENDAR', bytes),
        ('MKCOL', bytes),
        ('MKREDIRECTREF', bytes),
        ('MKWORKSPACE', bytes),
        ('MOVE', bytes),
        ('OPTIONS', bytes),
        ('ORDERPATCH', bytes),
        ('PATCH', bytes),
        ('POST', bytes),
        ('PRI', bytes),
        ('PROPFIND', bytes),
        ('PROPPATCH', bytes),
        ('PUT', bytes),
        ('REBIND', bytes),
        ('REPORT', bytes),
        ('SEARCH', bytes),
        ('TRACE', bytes),
        ('UNBIND', bytes),
        ('UNCHECKOUT', bytes),
        ('UNLINK', bytes),
        ('UNLOCK', bytes),
        ('UPDATE', bytes),
        ('UPDATEREDIRECTREF', bytes),
        ('VERSION_CONTROL', bytes),
        ('STAR', bytes),
    ],
)

httpMethods = HttpMethods(
    b'ACL',
    b'BASELINE-CONTROL',
    b'BIND',
    b'CHECKIN',
    b'CHECKOUT',
    b'CONNECT',
    b'COPY',
    b'DELETE',
    b'GET',
    b'HEAD',
    b'LABEL',
    b'LINK',
    b'LOCK',
    b'MERGE',
    b'MKACTIVITY',
    b'MKCALENDAR',
    b'MKCOL',
    b'MKREDIRECTREF',
    b'MKWORKSPACE',
    b'MOVE',
    b'OPTIONS',
    b'ORDERPATCH',
    b'PATCH',
    b'POST',
    b'PRI',
    b'PROPFIND',
    b'PROPPATCH',
    b'PUT',
    b'REBIND',
    b'REPORT',
    b'SEARCH',
    b'TRACE',
    b'UNBIND',
    b'UNCHECKOUT',
    b'UNLINK',
    b'UNLOCK',
    b'UPDATE',
    b'UPDATEREDIRECTREF',
    b'VERSION-CONTROL',
    b'*',
)
