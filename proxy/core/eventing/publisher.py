# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


class EventingPublisher:
    """EventingTopic provides utilities around pubsub functionalities
    within a particular topic context.

    Each topic a unix socket domain file on disk.  Publishers from
    within proxy.py instance or from outside can publish to these
    topics.

    Payload published to a topic can be consumed by multiple subscriber,
    which can be across CPU processes.  Subscribers can ideally also
    exist outside of proxy.py instance because topics are on-disk.

    Subscribers will only receive events published after they
    have completed the subscription phase.  No buffering/caching/redelivery/ack
    of payload is currently implemented.
    """

    def publish(self, topic: str) -> None:
        """Publish payload into a topic."""
        pass
