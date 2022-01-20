# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       pac
"""
from typing import Any, List, Tuple, Optional

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser
from .protocols import httpProtocolTypes
from ..responses import okResponse
from ...common.flag import flags
from ...common.utils import text_, bytes_
from ...common.constants import DEFAULT_PAC_FILE, DEFAULT_PAC_FILE_URL_PATH


flags.add_argument(
    '--pac-file',
    type=str,
    default=DEFAULT_PAC_FILE,
    help='A file (Proxy Auto Configuration) or string to serve when '
    'the server receives a direct file request. '
    'Using this option enables proxy.HttpWebServerPlugin.',
)
flags.add_argument(
    '--pac-file-url-path',
    type=str,
    default=text_(DEFAULT_PAC_FILE_URL_PATH),
    help='Default: %s. Web server path to serve the PAC file.' %
    text_(DEFAULT_PAC_FILE_URL_PATH),
)


class HttpWebServerPacFilePlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pac_file_response: Optional[memoryview] = None
        self.cache_pac_file_response()

    def routes(self) -> List[Tuple[int, str]]:
        if self.flags.pac_file_url_path:
            return [
                (
                    httpProtocolTypes.HTTP, r'{0}$'.format(
                        text_(self.flags.pac_file_url_path),
                    ),
                ),
                (
                    httpProtocolTypes.HTTPS, r'{0}$'.format(
                        text_(self.flags.pac_file_url_path),
                    ),
                ),
            ]
        return []   # pragma: no cover

    def handle_request(self, request: HttpParser) -> None:
        if self.flags.pac_file and self.pac_file_response:
            self.client.queue(self.pac_file_response)

    def cache_pac_file_response(self) -> None:
        if self.flags.pac_file:
            try:
                with open(self.flags.pac_file, 'rb') as f:
                    content = f.read()
            except IOError:
                content = bytes_(self.flags.pac_file)
            self.pac_file_response = okResponse(
                content=content,
                headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                },
                conn_close=True,
                compress=False,
            )
