# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       acceptor
"""
import argparse

from abc import ABC, abstractmethod
from uuid import uuid4
from typing import Optional, Dict, Any, TypeVar, Generic, TYPE_CHECKING

from ..event import eventNames, EventQueue
from ...common.types import Readables, Writables

if TYPE_CHECKING:
    from ..connection import UpstreamConnectionPool

T = TypeVar('T')


class Work(ABC, Generic[T]):
    """Implement Work to hook into the event loop provided by Threadless process."""

    def __init__(
            self,
            work: T,
            flags: argparse.Namespace,
            event_queue: Optional[EventQueue] = None,
            uid: Optional[str] = None,
            upstream_conn_pool: Optional['UpstreamConnectionPool'] = None,
    ) -> None:
        # Work uuid
        self.uid: str = uid if uid is not None else uuid4().hex
        self.flags = flags
        # Eventing core queue
        self.event_queue = event_queue
        # Accept work
        self.work = work
        self.upstream_conn_pool = upstream_conn_pool

    @abstractmethod
    async def get_events(self) -> Dict[int, int]:
        """Return sockets and events (read or write) that we are interested in."""
        return {}   # pragma: no cover

    @abstractmethod
    async def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Handle readable and writable sockets.

        Return True to shutdown work."""
        return False    # pragma: no cover

    def initialize(self) -> None:
        """Perform any resource initialization."""
        pass    # pragma: no cover

    def is_inactive(self) -> bool:
        """Return True if connection should be considered inactive."""
        return False    # pragma: no cover

    def shutdown(self) -> None:
        """Implementation must close any opened resources here
        and call super().shutdown()."""
        self.publish_event(
            event_name=eventNames.WORK_FINISHED,
            event_payload={},
            publisher_id=self.__class__.__name__,
        )

    def run(self) -> None:
        """run() method is not used by Threadless.  It's here for backward
        compatibility with threaded mode where work class is started as
        a separate thread.
        """
        pass    # pragma: no cover

    def publish_event(
            self,
            event_name: int,
            event_payload: Dict[str, Any],
            publisher_id: Optional[str] = None,
    ) -> None:
        """Convenience method provided to publish events into the global event queue."""
        if not self.flags.enable_events:
            return
        assert self.event_queue
        self.event_queue.publish(
            self.uid,
            event_name,
            event_payload,
            publisher_id,
        )
