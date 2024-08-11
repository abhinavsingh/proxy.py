# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import glob
from typing import TYPE_CHECKING, Any, Dict, List, Tuple
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from multiprocessing.synchronize import Lock

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser
from .protocols import httpProtocolTypes
from ...core.event import EventQueue, EventSubscriber, eventNames
from ...common.flag import flags
from ...common.utils import text_, build_http_response
from ...common.constants import (
    DEFAULT_ENABLE_METRICS, DEFAULT_METRICS_URL_PATH,
    DEFAULT_METRICS_DIRECTORY_PATH,
)


if TYPE_CHECKING:
    from prometheus_client.registry import Collector


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

class MetricsStorage:

    def __init__(self, lock: Lock) -> None:
        self._lock = lock

    def get_counter(self, name: str, default: float = 0.0) -> float:
        with self._lock:
            return self._get_counter(name, default)

    def _get_counter(self, name: str, default: float = 0.0) -> float:
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.counter')
        if not os.path.exists(path):
            return default
        return float(Path(path).read_text(encoding='utf-8').strip())

    def incr_counter(self, name: str, by: float = 1.0) -> None:
        with self._lock:
            self._incr_counter(name, by)

    def _incr_counter(self, name: str, by: float = 1.0) -> None:
        current = self._get_counter(name)
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.counter')
        Path(path).write_text(str(current + by), encoding='utf-8')

    def get_gauge(self, name: str, default: float = 0.0) -> float:
        with self._lock:
            return self._get_gauge(name, default)

    def _get_gauge(self, name: str, default: float = 0.0) -> float:
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.gauge')
        if not os.path.exists(path):
            return default
        return float(Path(path).read_text(encoding='utf-8').strip())

    def set_gauge(self, name: str, value: float) -> None:
        """Stores a single values."""
        with self._lock:
            self._set_gauge(name, value)

    def _set_gauge(self, name: str, value: float) -> None:
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.gauge')
        with open(path, 'w', encoding='utf-8') as g:
            g.write(str(value))


def get_collector(metrics_lock: Lock) -> 'Collector':
    # pylint: disable=import-outside-toplevel
    from prometheus_client.registry import Collector

    class MetricsCollector(Collector):

        def __init__(self, metrics_lock: Lock) -> None:
            self.storage = MetricsStorage(metrics_lock)

        def collect(self):
            """Serves from aggregates metrics managed by MetricsEventSubscriber."""
            # pylint: disable=import-outside-toplevel
            from prometheus_client.core import CounterMetricFamily

            counter = CounterMetricFamily(
                'proxypy_counter',
                'Total count of proxypy events',
                labels=['proxypy'],
            )
            counter.add_metric(
                ['work_started'],
                self.storage.get_counter('work_started'),
            )
            counter.add_metric(
                ['request_complete'],
                self.storage.get_counter('request_complete'),
            )
            counter.add_metric(
                ['work_finished'],
                self.storage.get_counter('work_finished'),
            )
            yield counter

    return MetricsCollector(metrics_lock)


class MetricsEventSubscriber:

    def __init__(self, event_queue: EventQueue, metrics_lock: Lock) -> None:
        """Aggregates metric events pushed by proxy.py core and plugins.

        1) Metrics are stored and managed by multiprocessing safe MetricsStorage
        2) Collection must be done via MetricsWebServerPlugin endpoint
        """
        self.storage = MetricsStorage(metrics_lock)
        self.subscriber = EventSubscriber(
            event_queue,
            callback=lambda event: MetricsEventSubscriber.callback(self.storage, event),
        )

    def _setup_metrics_directory(self) -> None:
        os.makedirs(DEFAULT_METRICS_DIRECTORY_PATH, exist_ok=True)
        patterns = ['*.counter', '*.gauge']
        for pattern in patterns:
            files = glob.glob(os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, pattern))
            for file_path in files:
                try:
                    os.remove(file_path)
                except OSError as e:
                    print(f'Error deleting file {file_path}: {e}')

    def __enter__(self) -> 'MetricsEventSubscriber':
        self._setup_metrics_directory()
        self.subscriber.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.subscriber.shutdown()

    @staticmethod
    def callback(storage: MetricsStorage, event: Dict[str, Any]) -> None:
        if event['event_name'] == eventNames.WORK_STARTED:
            storage.incr_counter('work_started')
        elif event['event_name'] == eventNames.REQUEST_COMPLETE:
            storage.incr_counter('request_complete')
        elif event['event_name'] == eventNames.WORK_FINISHED:
            storage.incr_counter('work_finished')
        else:
            print('Unhandled', event)


class MetricsWebServerPlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # pylint: disable=import-outside-toplevel
        from prometheus_client.core import CollectorRegistry
        from prometheus_client.registry import Collector

        super().__init__(*args, **kwargs)
        self.registry = CollectorRegistry()
        self.registry.register(get_collector(self.flags.metrics_lock))

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

        status, headers, output = _bake_output(
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
