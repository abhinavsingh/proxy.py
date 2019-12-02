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
import multiprocessing
import selectors
import socket
import threading
# import time
from multiprocessing import connection
from multiprocessing.reduction import send_handle, recv_handle
from typing import Optional, Type, Tuple

from ..threadless import ThreadlessWork, Threadless
from ..event import EventQueue, eventNames
from ...common.flags import Flags

logger = logging.getLogger(__name__)


class Acceptor(multiprocessing.Process):
    """Socket client acceptor.

    Accepts client connection over received server socket handle and
    starts a new work thread.
    """

    lock = multiprocessing.Lock()

    def __init__(
            self,
            idd: int,
            work_queue: connection.Connection,
            flags: Flags,
            work_klass: Type[ThreadlessWork],
            event_queue: Optional[EventQueue] = None) -> None:
        super().__init__()
        self.idd = idd
        self.work_queue: connection.Connection = work_queue
        self.flags = flags
        self.work_klass = work_klass
        self.event_queue = event_queue

        self.running = multiprocessing.Event()
        self.selector: Optional[selectors.DefaultSelector] = None
        self.sock: Optional[socket.socket] = None
        self.threadless_process: Optional[Threadless] = None
        self.threadless_client_queue: Optional[connection.Connection] = None

    def start_threadless_process(self) -> None:
        pipe = multiprocessing.Pipe()
        self.threadless_client_queue = pipe[0]
        self.threadless_process = Threadless(
            client_queue=pipe[1],
            flags=self.flags,
            work_klass=self.work_klass,
            event_queue=self.event_queue
        )
        self.threadless_process.start()
        logger.debug('Started process %d', self.threadless_process.pid)

    def shutdown_threadless_process(self) -> None:
        assert self.threadless_process and self.threadless_client_queue
        logger.debug('Stopped process %d', self.threadless_process.pid)
        self.threadless_process.running.set()
        self.threadless_process.join()
        self.threadless_client_queue.close()

    def start_work(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        if self.flags.threadless and \
                self.threadless_client_queue and \
                self.threadless_process:
            self.threadless_client_queue.send(addr)
            send_handle(
                self.threadless_client_queue,
                conn.fileno(),
                self.threadless_process.pid
            )
            conn.close()
        else:
            work = self.work_klass(
                fileno=conn.fileno(),
                addr=addr,
                flags=self.flags,
                event_queue=self.event_queue
            )
            work_thread = threading.Thread(target=work.run)
            work_thread.daemon = True
            work.publish_event(
                event_name=eventNames.WORK_STARTED,
                event_payload={'fileno': conn.fileno(), 'addr': addr},
                publisher_id=self.__class__.__name__
            )
            work_thread.start()

    def run_once(self) -> None:
        assert self.selector and self.sock
        with self.lock:
            events = self.selector.select(timeout=1)
            if len(events) == 0:
                return
            conn, addr = self.sock.accept()
        # now = time.time()
        # fileno: int = conn.fileno()
        self.start_work(conn, addr)
        # logger.info('Work started for fd %d in %f seconds', fileno, time.time() - now)

    def run(self) -> None:
        self.selector = selectors.DefaultSelector()
        fileno = recv_handle(self.work_queue)
        self.work_queue.close()
        self.sock = socket.fromfd(
            fileno,
            family=self.flags.family,
            type=socket.SOCK_STREAM
        )
        try:
            self.selector.register(self.sock, selectors.EVENT_READ)
            if self.flags.threadless:
                self.start_threadless_process()
            while not self.running.is_set():
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            self.selector.unregister(self.sock)
            if self.flags.threadless:
                self.shutdown_threadless_process()
            self.sock.close()
            logger.debug('Acceptor#%d shutdown', self.idd)
