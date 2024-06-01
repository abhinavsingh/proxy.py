# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import Set, Union, Optional

from proxy import metrics
from proxy.core.event import eventNames


logger = logging.getLogger(__name__)


class MetricEmisorMixin:
    """MetricEmisorMixin provides methods to publish metrics."""

    def _can_emit_metrics(self):
        if self.flags.enable_events and self.flags.enable_metrics:
            assert self.event_queue
            return True
        logging.info('Metrics disabled')
        return False


    def emit_metric(self, metric: metrics.Metric) -> None:
        if self._can_emit_metrics():
            self.event_queue.publish(
                request_id=self.uid,
                event_name=eventNames.METRIC,
                event_payload=metric,
                publisher_id=self.__class__.__qualname__,
            )

    def emit_metric_counter(
        self,
        name: str,
        increment: int | float=1,
        description: Optional[str]=None,
        tags: Optional[set[str]]=None,
    ) -> None:
        if self._can_emit_metrics():
            self.emit_metric(metrics.Counter(name, increment, description, tags))

    def emit_metric_gauge(
        self,
        name: str,
        value: Union[int, float],
        description: Optional[str]=None,
        tags: Optional[Set[str]]=None,
    ) -> None:
        if self._can_emit_metrics():
            self.emit_metric(metrics.Gauge(name, value, description, tags))
