# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket

from abc import ABC, abstractmethod
from uuid import uuid4, UUID
from typing import Optional, Dict, List, Union, Any

from ..event import eventNames, EventQueue
from ..connection import TcpClientConnection
from ...common.flags import Flags
from ...common.types import HasFileno


class ThreadlessWork(ABC):
    """Implement ThreadlessWork to hook into the event loop provided by Threadless process."""

    def __init__(
            self,
            client: TcpClientConnection,
            flags: Optional[Flags],
            event_queue: Optional[EventQueue] = None,
            uid: Optional[UUID] = None) -> None:
        self.client = client
        self.flags = flags if flags else Flags()
        self.event_queue = event_queue
        self.uid: UUID = uid if uid is not None else uuid4()

    @abstractmethod
    def initialize(self) -> None:
        pass    # pragma: no cover

    @abstractmethod
    def is_inactive(self) -> bool:
        return False    # pragma: no cover

    @abstractmethod
    def get_events(self) -> Dict[socket.socket, int]:
        return {}   # pragma: no cover

    @abstractmethod
    def handle_events(
            self,
            readables: List[Union[int, HasFileno]],
            writables: List[Union[int, HasFileno]]) -> bool:
        """Return True to shutdown work."""
        return False    # pragma: no cover

    @abstractmethod
    def run(self) -> None:
        pass

    def publish_event(
            self,
            event_name: int,
            event_payload: Dict[str, Any],
            publisher_id: Optional[str] = None) -> None:
        if not self.flags.enable_events:
            return
        assert self.event_queue
        self.event_queue.publish(
            self.uid.hex,
            event_name,
            event_payload,
            publisher_id
        )

    def shutdown(self) -> None:
        """Must close any opened resources and call super().shutdown()."""
        self.publish_event(
            event_name=eventNames.WORK_FINISHED,
            event_payload={},
            publisher_id=self.__class__.__name__
        )
