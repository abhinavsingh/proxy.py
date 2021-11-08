# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


class EventingSubscriber:
    """EventingSubscriber provides subscription utilities for a topic."""

    def __init__(self, topic: str) -> None:
        self.topic = topic

    def subscribe(self) -> None:
        """Subscribe to topic."""
        pass

    def unsubscribe(self) -> None:
        """Unsubscribe from topic"""
        pass
