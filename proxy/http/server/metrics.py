# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any, Dict, List, Tuple

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser
from .protocols import httpProtocolTypes
from ...core.event import EventQueue, EventSubscriber, eventNames
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


class MetricsSubscriber:

    def __init__(self, event_queue: EventQueue) -> None:
        self.subscriber = EventSubscriber(
            event_queue,
            callback=MetricsSubscriber.callback,
        )

    def shutdown(self) -> None:
        self.subscriber.shutdown()

    def setup(self) -> None:
        self.subscriber.setup()

    @staticmethod
    def callback(event: Dict[str, Any]) -> None:
        if event["event_name"] == eventNames.WORK_STARTED:
            print(event)
        elif event["event_name"] == eventNames.REQUEST_COMPLETE:
            print(event)
        elif event["event_name"] == eventNames.WORK_FINISHED:
            print(event)
        else:
            print("Unhandled", event)
