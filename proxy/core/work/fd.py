import socket
import logging

from typing import Any, Optional, Tuple

from ...common.types import TcpOrTlsSocket
from ..event import eventNames
from .threadless import Threadless

logger = logging.getLogger(__name__)


class ThreadlessFd(Threadless):

    def work(
            self,
            *args: Any,
            **kwargs: Any,
    ) -> None:
        fileno: int = args[0]
        addr: Optional[Tuple[str, int]] = kwargs.get('addr', None)
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
