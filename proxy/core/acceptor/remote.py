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

from typing import Optional

from multiprocessing.reduction import recv_handle

from ..connection import TcpClientConnection
from ..event import eventNames

from .threadless import Threadless

logger = logging.getLogger(__name__)


class RemoteExecutor(Threadless):
    """RemoteExecutor receives work over a Connection object.
    RemoteExecutor uses ``recv_handle`` to accept incoming work.
    """

    def work_queue_fileno(self) -> Optional[int]:
        return self.work_queue.fileno()

    def close_work_queue(self) -> None:
        self.work_queue.close()

    def receive_from_work_queue(self) -> None:
        # Acceptor will not send address for
        # unix socket domain environments.
        addr = None
        if not self.flags.unix_socket_path:
            addr = self.work_queue.recv()
        fileno = recv_handle(self.work_queue)
        self.works[fileno] = self.flags.work_klass(
            TcpClientConnection(conn=self._fromfd(fileno), addr=addr),
            flags=self.flags,
            event_queue=self.event_queue,
        )
        self.works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        try:
            self.works[fileno].initialize()
        except Exception as e:
            logger.exception(
                'Exception occurred during initialization',
                exc_info=e,
            )
            self._cleanup(fileno)
