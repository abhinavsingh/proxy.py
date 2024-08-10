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
from urllib.parse import parse_qs, urlparse

from prometheus_client.core import REGISTRY, CounterMetricFamily
from prometheus_client.registry import Collector
from prometheus_client.exposition import _bake_output

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser
from .protocols import httpProtocolTypes
from ...core.event import EventQueue, EventSubscriber, eventNames
from ...common.flag import flags
from ...common.utils import text_, build_http_response
from ...common.constants import (
    DEFAULT_ENABLE_METRICS, DEFAULT_METRICS_URL_PATH,
)


flags.add_argument(
    '--enable-metrics',
    action='store_true',
    default=DEFAULT_ENABLE_METRICS,
    help='Default: False.  Enables metrics.',
)

flags.add_argument(
    '--metrics-path',
    type=str,
    default=text_(DEFAULT_METRICS_URL_PATH),
    help='Default: %s. Web server path to serve proxy.py metrics.'
    % text_(DEFAULT_METRICS_URL_PATH),
)


class MetricsWebServerPlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def routes(self) -> List[Tuple[int, str]]:
        if self.flags.metrics_path:
            return [
                (
                    httpProtocolTypes.HTTP,
                    r'{0}$'.format(
                        text_(self.flags.metrics_path),
                    ),
                ),
                (
                    httpProtocolTypes.HTTPS,
                    r'{0}$'.format(
                        text_(self.flags.metrics_path),
                    ),
                ),
            ]
        return []  # pragma: no cover

    def handle_request(self, request: HttpParser) -> None:
        status, headers, output = _bake_output(
            REGISTRY,
            (
                request.header(b'Accept').decode()
                if request.has_header(b'Accept')
                else '*/*'
            ),
            (
                request.header(b'Accept-Encoding').decode()
                if request.has_header(b'Accept-Encoding')
                else None
            ),
            parse_qs(urlparse(request.path).query),
            False,
        )
        statuses = status.split(' ', maxsplit=1)
        response = build_http_response(
            int(statuses[0]),
            reason=statuses[1].encode(),
            headers={key.encode(): value.encode() for key, value in headers},
            body=output,
        )
        self.client.queue(memoryview(response))


class MetricsCollector(Collector):
    def __init__(self) -> None:
        self.work_started = 0
        self.request_complete = 0
        self.work_finished = 0

    def collect(self):
        """Serves from aggregates metrics managed by MetricsEventSubscriber."""
        counter = CounterMetricFamily(
            'proxypy_counter',
            'Total count of proxypy events',
            labels=['proxypy'],
        )
        counter.add_metric(['work_started'], self.work_started)
        counter.add_metric(['request_complete'], self.request_complete)
        counter.add_metric(['work_finished'], self.work_finished)
        yield counter


class MetricsEventSubscriber:

    def __init__(self, event_queue: EventQueue) -> None:
        """Aggregates metric events pushed by proxy.py core and plugins.

        1) Metrics are kept in-memory
        2) Collection must be done via MetricsWebServerPlugin endpoint
        """
        self.registry = REGISTRY
        self.collector = MetricsCollector()
        self.subscriber = EventSubscriber(
            event_queue,
            callback=lambda event: MetricsEventSubscriber.callback(
                self.collector,
                event,
            ),
        )

    def __enter__(self) -> 'MetricsEventSubscriber':
        self.subscriber.setup()
        self.registry.register(self.collector)
        return self

    def __exit__(self, *args: Any) -> None:
        self.subscriber.shutdown()

    @staticmethod
    def callback(collector: MetricsCollector, event: Dict[str, Any]) -> None:
        print(event)
        if event['event_name'] == eventNames.WORK_STARTED:
            collector.work_started += 1
        elif event['event_name'] == eventNames.REQUEST_COMPLETE:
            collector.request_complete += 1
        elif event['event_name'] == eventNames.WORK_FINISHED:
            collector.work_finished += 1
        else:
            print('Unhandled', event)
