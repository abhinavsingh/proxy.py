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
       url
"""
from typing import List, Tuple, Optional

from proxy.common.utils import text_
from proxy.http.exception import HttpProtocolException
from proxy.common.constants import (
    AT, COLON, SLASH, DEFAULT_ALLOWED_URL_SCHEMES,
)


class Url:
    """``urllib.urlparse`` doesn't work for proxy.py, so we wrote a simple URL.

    Currently, URL only implements what is necessary for HttpParser to work.
    """

    def __init__(
            self,
            scheme: Optional[bytes] = None,
            username: Optional[bytes] = None,
            password: Optional[bytes] = None,
            hostname: Optional[bytes] = None,
            port: Optional[int] = None,
            remainder: Optional[bytes] = None,
    ) -> None:
        self.scheme: Optional[bytes] = scheme
        self.username: Optional[bytes] = username
        self.password: Optional[bytes] = password
        self.hostname: Optional[bytes] = hostname
        self.port: Optional[int] = port
        self.remainder: Optional[bytes] = remainder

    @property
    def has_credentials(self) -> bool:
        """Returns true if both username and password components are present."""
        return self.username is not None and self.password is not None

    def __str__(self) -> str:
        url = ''
        if self.scheme:
            url += '{0}://'.format(text_(self.scheme))
        if self.hostname:
            url += text_(self.hostname)
        if self.port:
            url += ':{0}'.format(self.port)
        if self.remainder:
            url += text_(self.remainder)
        return url

    @classmethod
    def from_bytes(cls, raw: bytes, allowed_url_schemes: Optional[List[bytes]] = None) -> 'Url':
        """A URL within proxy.py core can have several styles,
        because proxy.py supports both proxy and web server use cases.

        Example:
        For a Web server, url is like ``/`` or ``/get`` or ``/get?key=value``
        For a HTTPS connect tunnel, url is like ``httpbin.org:443``
        For a HTTP proxy request, url is like ``http://httpbin.org/get``

        proxy.py internally never expects a https scheme in the request line.
        But `Url` class provides support for parsing any scheme present in the URLs.
        e.g. ftp, icap etc.

        If a url with no scheme is parsed, e.g. ``//host/abc.js``, then scheme
        defaults to `http`.

        Further:
        1) URL may contain unicode characters
        2) URL may contain IPv4 and IPv6 format addresses instead of domain names
        """
        # SLASH == 47, check if URL starts with single slash but not double slash
        starts_with_single_slash = raw[0] == 47
        starts_with_double_slash = starts_with_single_slash and \
            len(raw) >= 2 and \
            raw[1] == 47
        if starts_with_single_slash and \
                not starts_with_double_slash:
            return cls(remainder=raw)
        scheme = None
        rest = None
        if not starts_with_double_slash:
            # Find scheme
            parts = raw.split(b'://', 1)
            if len(parts) == 2:
                scheme = parts[0]
                rest = parts[1]
                if scheme not in (allowed_url_schemes or DEFAULT_ALLOWED_URL_SCHEMES):
                    raise HttpProtocolException(
                        'Invalid scheme received in the request line %r' % raw,
                    )
        else:
            rest = raw[len(SLASH + SLASH):]
        if scheme is not None or starts_with_double_slash:
            assert rest is not None
            parts = rest.split(SLASH, 1)
            username, password, host, port = Url._parse(parts[0])
            return cls(
                scheme=scheme if not starts_with_double_slash else b'http',
                username=username,
                password=password,
                hostname=host,
                port=port,
                remainder=None if len(parts) == 1 else (
                    SLASH + parts[1]
                ),
            )
        username, password, host, port = Url._parse(raw)
        return cls(username=username, password=password, hostname=host, port=port)

    @staticmethod
    def _parse(raw: bytes) -> Tuple[
            Optional[bytes],
            Optional[bytes],
            bytes,
            Optional[int],
    ]:
        split_at = raw.split(AT, 1)
        username, password = None, None
        if len(split_at) == 2:
            username, password = split_at[0].split(COLON)
        parts = split_at[-1].split(COLON, 2)
        num_parts = len(parts)
        port: Optional[int] = None
        # No port found
        if num_parts == 1:
            return username, password, parts[0], None
        # Host and port found
        if num_parts == 2:
            return username, password, COLON.join(parts[:-1]), int(parts[-1])
        # More than a single COLON i.e. IPv6 scenario
        try:
            # Try to resolve last part as an int port
            last_token = parts[-1].split(COLON)
            port = int(last_token[-1])
            host = COLON.join(parts[:-1]) + COLON + \
                COLON.join(last_token[:-1])
        except ValueError:
            # If unable to convert last part into port,
            # treat entire data as host
            host, port = raw, None
        # patch up invalid ipv6 scenario
        rhost = host.decode('utf-8')
        if COLON.decode('utf-8') in rhost and \
                rhost[0] != '[' and \
                rhost[-1] != ']':
            host = b'[' + host + b']'
        return username, password, host, port
