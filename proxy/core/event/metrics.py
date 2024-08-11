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
from typing import Any, Dict
from pathlib import Path
from multiprocessing.synchronize import Lock

from ...core.event import EventQueue, EventSubscriber, eventNames
from ...common.constants import DEFAULT_METRICS_DIRECTORY_PATH


class MetricsStorage:

    def __init__(self, lock: Lock) -> None:
        self._lock = lock

    def get_counter(self, name: str) -> float:
        with self._lock:
            return self._get_counter(name)

    def _get_counter(self, name: str) -> float:
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.counter')
        if not os.path.exists(path):
            return 0
        return float(Path(path).read_text(encoding='utf-8').strip())

    def incr_counter(self, name: str, by: float = 1.0) -> None:
        with self._lock:
            self._incr_counter(name, by)

    def _incr_counter(self, name: str, by: float = 1.0) -> None:
        current = self._get_counter(name)
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.counter')
        Path(path).write_text(str(current + by), encoding='utf-8')

    def get_gauge(self, name: str) -> float:
        with self._lock:
            return self._get_gauge(name)

    def _get_gauge(self, name: str) -> float:
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.gauge')
        if not os.path.exists(path):
            return 0
        return float(Path(path).read_text(encoding='utf-8').strip())

    def set_gauge(self, name: str, value: float) -> None:
        """Stores a single values."""
        with self._lock:
            self._set_gauge(name, value)

    def _set_gauge(self, name: str, value: float) -> None:
        path = os.path.join(DEFAULT_METRICS_DIRECTORY_PATH, f'{name}.gauge')
        with open(path, 'w', encoding='utf-8') as g:
            g.write(str(value))


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

    def setup(self) -> None:
        self._setup_metrics_directory()
        self.subscriber.setup()

    def shutdown(self) -> None:
        self.subscriber.shutdown()

    def __enter__(self) -> 'MetricsEventSubscriber':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

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
