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
import logging
from typing import Any, TypeVar, Optional

from ..event import eventNames
from .threadless import Threadless
from ...common.types import HostPort, TcpOrTlsSocket


T = TypeVar('T')

logger = logging.getLogger(__name__)


class ThreadlessFdExecutor(Threadless[T]):

    def work(
            self,
            *args: Any,
            **kwargs: Any,
    ) -> None:
        fileno: int = kwargs['fileno']
        addr: Optional[HostPort] = kwargs.get('addr', None)
        conn: Optional[TcpOrTlsSocket] = \
            kwargs.get('conn', None)
        conn = conn or socket.fromfd(
            fileno, family=socket.AF_INET if self.flags.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )
        uid = '%s-%s-%s' % (self.iid, self._total, fileno)
        self.works[fileno] = self.flags.work_klass(
            self.flags.work_klass.create(
                conn=conn,
                addr=addr,
            ),
            flags=self.flags,
            event_queue=self.event_queue,
            uid=uid,
            upstream_conn_pool=self._upstream_conn_pool,
        )
        self.works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        try:
            self.works[fileno].initialize()
            self._total += 1
        except Exception as e:
            logger.exception(
                'Exception occurred during initialization',
                exc_info=e,
            )
            self._cleanup(fileno)
