# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       ws
       onmessage
"""
import logging
from typing import List, Tuple, Dict, Any

from proxy.http.parser import HttpParser
from proxy.http.server import HttpWebServerBasePlugin, httpProtocolTypes
from proxy.http.responses import okResponse
from proxy.core.event import EventSubscriber
from proxy import metrics

from prometheus_client.exposition import generate_latest
from prometheus_client.registry import REGISTRY
from prometheus_client import Counter


logger = logging.getLogger(__name__)


class Prometheus(HttpWebServerBasePlugin):
    """
    Expose metrics on prometheus format.
    Requires to install prometheus client (`pip install prometheus-client`)
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.subscriber = EventSubscriber(
            self.event_queue,
            callback=self.process_metric_event
        )
        self.subscriber.setup()
        self.metrics: Dict[str, Any] = {}

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, r'/metrics$'),
            (httpProtocolTypes.HTTPS, r'/metrics$'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        self.emit_metric_counter("prometheus_requests")
        if request.path == b'/metrics':
            self.client.queue(okResponse(generate_latest()))

    def process_metric_event(self, event: Dict[str, Any]) -> None:
        payload = event["event_payload"]
        if not isinstance(payload, metrics.Metric):
            return
        try:
            logger.info(event)
            if isinstance(payload, metrics.Counter):
                name = f"counter_{payload.name}"

                if name not in REGISTRY._names_to_collectors:
                    Counter(name, payload.description)
                counter = REGISTRY._names_to_collectors.get(name)
                counter.inc(payload.increment)

        except:
            logger.exception("Problems")


