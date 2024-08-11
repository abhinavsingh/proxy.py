# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any, List, Tuple, Generator, cast
from urllib.parse import parse_qs, urlparse
from multiprocessing.synchronize import Lock

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser
from .protocols import httpProtocolTypes
from ...common.flag import flags
from ...common.utils import text_, build_http_response
from ...common.constants import (
    DEFAULT_ENABLE_METRICS, DEFAULT_METRICS_URL_PATH,
)
from ...core.event.metrics import MetricsStorage


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


def get_collector(metrics_lock: Lock) -> Any:
    # pylint: disable=import-outside-toplevel
    from prometheus_client.core import Metric
    from prometheus_client.registry import Collector

    class MetricsCollector(Collector):

        def __init__(self, metrics_lock: Lock) -> None:
            self.storage = MetricsStorage(metrics_lock)

        def collect(self) -> Generator[Metric, None, None]:
            """Serves from aggregates metrics managed by MetricsEventSubscriber."""
            # pylint: disable=import-outside-toplevel
            from prometheus_client.core import (
                GaugeMetricFamily, CounterMetricFamily,
            )

            started = self.storage.get_counter('work_started')
            finished = self.storage.get_counter('work_finished')

            work_started = CounterMetricFamily(
                'proxypy_work_started',
                'Total work accepted and started by proxy.py core',
            )
            work_started.add_metric(
                ['proxypy_work_started'],
                started,
            )
            yield work_started

            request_complete = CounterMetricFamily(
                'proxypy_work_request_received',
                'Total work finished sending initial request',
            )
            request_complete.add_metric(
                ['proxypy_work_request_received'],
                self.storage.get_counter('request_complete'),
            )
            yield request_complete

            work_finished = CounterMetricFamily(
                'proxypy_work_finished',
                'Total work finished by proxy.py core',
            )
            work_finished.add_metric(
                ['work_finished'],
                finished,
            )
            yield work_finished

            ongoing_work = GaugeMetricFamily(
                'proxypy_work_active',
                'Total work under active execution',
                value=started - finished,
            )
            yield ongoing_work

    return MetricsCollector(metrics_lock)


class MetricsWebServerPlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # pylint: disable=import-outside-toplevel
        from prometheus_client.core import CollectorRegistry
        from prometheus_client.registry import Collector

        self.registry = CollectorRegistry()
        self.registry.register(cast(Collector, get_collector(self.flags.metrics_lock)))

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
        # pylint: disable=import-outside-toplevel
        from prometheus_client.exposition import _bake_output

        # flake8: noqa
        status, headers, output = _bake_output(  # type: ignore[no-untyped-call]
            self.registry,
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
