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
from typing import Any, List, Tuple

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser
from .protocols import httpProtocolTypes
from ...common.flag import flags
from ...common.utils import text_
from ...common.constants import DEFAULT_METRICS_URL_PATH


flags.add_argument(
    "--metrics-path",
    type=str,
    default=text_(DEFAULT_METRICS_URL_PATH),
    help="Default: %s. Web server path to serve proxy.py metrics."
    % text_(DEFAULT_METRICS_URL_PATH),
)


class MetricsPlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def routes(self) -> List[Tuple[int, str]]:
        if self.flags.metrics_path:
            return [
                (
                    httpProtocolTypes.HTTP,
                    r"{0}$".format(
                        text_(self.flags.metrics_path),
                    ),
                ),
                (
                    httpProtocolTypes.HTTPS,
                    r"{0}$".format(
                        text_(self.flags.metrics_path),
                    ),
                ),
            ]
        return []  # pragma: no cover

    def handle_request(self, request: HttpParser) -> None:
        return None
