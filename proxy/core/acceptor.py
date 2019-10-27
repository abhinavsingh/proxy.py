# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import asyncio
import contextlib
import logging
import multiprocessing
import os
import selectors
import socket
import ssl
import threading
import uuid
from abc import ABC, abstractmethod
from multiprocessing import connection
from multiprocessing.reduction import send_handle, recv_handle
from typing import List, Optional, Type, Tuple, Dict, Generator, Union, Any

from .event import EventQueue, EventDispatcher, eventNames
from ..common.constants import DEFAULT_TIMEOUT
from ..common.flags import Flags
from ..common.types import HasFileno

logger = logging.getLogger(__name__)


class ThreadlessWork(ABC):
    """Implement ThreadlessWork to hook into the event loop provided by Threadless process."""

    @abstractmethod
    def __init__(
            self,
            fileno: int,
            addr: Tuple[str, int],
            flags: Optional[Flags],
            event_queue: Optional[EventQueue] = None,
            uid: Optional[str] = None) -> None:
        self.fileno = fileno
        self.addr = addr
        self.flags = flags if flags else Flags()

        self.event_queue = event_queue
        self.uid: str = uid if uid is not None else uuid.uuid4().hex

    def publish_event(
            self,
            event_name: int,
            event_payload: Dict[str, Any],
            publisher_id: Optional[str] = None) -> None:
        if not self.flags.enable_events:
            return
        assert self.event_queue
        self.event_queue.publish(
            self.uid,
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
    def handle_events(self,
                      readables: List[Union[int, HasFileno]],
                      writables: List[Union[int, HasFileno]]) -> bool:
        """Return True to shutdown work."""
        return False    # pragma: no cover

    @abstractmethod
    def run(self) -> None:
        pass


class AcceptorPool:
    """AcceptorPool.

    Pre-spawns worker processes to utilize all cores available on the system.  Server socket connection is
    dispatched over a pipe to workers.  Each worker accepts incoming client request and spawns a
    separate thread to handle the client request.
    """

    def __init__(self, flags: Flags, work_klass: Type[ThreadlessWork]) -> None:
        self.flags = flags
        self.running: bool = False
        self.socket: Optional[socket.socket] = None
        self.acceptors: List[Acceptor] = []
        self.work_queues: List[connection.Connection] = []
        self.work_klass = work_klass

        self.event_queue: Optional[EventQueue] = None
        self.event_dispatcher: Optional[EventDispatcher] = None
        self.event_dispatcher_thread: Optional[threading.Thread] = None
        self.event_dispatcher_shutdown: Optional[threading.Event] = None
        if self.flags.enable_events:
            self.event_queue = EventQueue()

    def listen(self) -> None:
        self.socket = socket.socket(self.flags.family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((str(self.flags.hostname), self.flags.port))
        self.socket.listen(self.flags.backlog)
        self.socket.setblocking(False)
        logger.info(
            'Listening on %s:%d' %
            (self.flags.hostname, self.flags.port))

    def start_workers(self) -> None:
        """Start worker processes."""
        for acceptor_id in range(self.flags.num_workers):
            work_queue = multiprocessing.Pipe()
            acceptor = Acceptor(
                idd=acceptor_id,
                work_queue=work_queue[1],
                flags=self.flags,
                work_klass=self.work_klass,
                event_queue=self.event_queue
            )
            acceptor.start()
            logger.debug('Started acceptor process %d', acceptor.pid)
            self.acceptors.append(acceptor)
            self.work_queues.append(work_queue[0])
        logger.info('Started %d workers' % self.flags.num_workers)

    def start_event_dispatcher(self) -> None:
        self.event_dispatcher_shutdown = threading.Event()
        assert self.event_dispatcher_shutdown
        assert self.event_queue
        self.event_dispatcher = EventDispatcher(
            shutdown=self.event_dispatcher_shutdown,
            event_queue=self.event_queue
        )
        self.event_dispatcher_thread = threading.Thread(
            target=self.event_dispatcher.run
        )
        self.event_dispatcher_thread.start()
        logger.debug('Thread ID: %d', self.event_dispatcher_thread.ident)

    def shutdown(self) -> None:
        logger.info('Shutting down %d workers' % self.flags.num_workers)
        if self.flags.enable_events:
            assert self.event_dispatcher_shutdown
            assert self.event_dispatcher_thread
            self.event_dispatcher_shutdown.set()
            self.event_dispatcher_thread.join()
            logger.debug('Shutdown of global event dispatcher thread %d successful', self.event_dispatcher_thread.ident)
        for acceptor in self.acceptors:
            acceptor.join()
        logger.debug('Acceptors shutdown')

    def setup(self) -> None:
        """Listen on port, setup workers and pass server socket to workers."""
        self.running = True
        self.listen()
        if self.flags.enable_events:
            self.start_event_dispatcher()
        self.start_workers()

        # Send server socket to all acceptor processes.
        assert self.socket is not None
        for index in range(self.flags.num_workers):
            send_handle(
                self.work_queues[index],
                self.socket.fileno(),
                self.acceptors[index].pid
            )
            self.work_queues[index].close()
        self.socket.close()


class Threadless(multiprocessing.Process):
    """Threadless provides an event loop.  Use it by implementing Threadless class.

    When --threadless option is enabled, each Acceptor process also
    spawns one Threadless process.  And instead of spawning new thread
    for each accepted client connection, Acceptor process sends
    accepted client connection to Threadless process over a pipe.

    HttpProtocolHandler implements ThreadlessWork class and hooks into the
    event loop provided by Threadless.
    """

    def __init__(
            self,
            client_queue: connection.Connection,
            flags: Flags,
            work_klass: Type[ThreadlessWork],
            event_queue: Optional[EventQueue] = None) -> None:
        super().__init__()
        self.client_queue = client_queue
        self.flags = flags
        self.work_klass = work_klass
        self.event_queue = event_queue

        self.works: Dict[int, ThreadlessWork] = {}
        self.selector: Optional[selectors.DefaultSelector] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    @contextlib.contextmanager
    def selected_events(self) -> Generator[Tuple[List[Union[int, HasFileno]],
                                                 List[Union[int, HasFileno]]],
                                           None, None]:
        events: Dict[socket.socket, int] = {}
        for work in self.works.values():
            events.update(work.get_events())
        assert self.selector is not None
        for fd in events:
            self.selector.register(fd, events[fd])
        ev = self.selector.select(timeout=1)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)
        yield (readables, writables)
        for fd in events.keys():
            self.selector.unregister(fd)

    async def handle_events(
            self, fileno: int,
            readables: List[Union[int, HasFileno]],
            writables: List[Union[int, HasFileno]]) -> bool:
        return self.works[fileno].handle_events(readables, writables)

    # TODO: Use correct future typing annotations
    async def wait_for_tasks(
            self, tasks: Dict[int, Any]) -> None:
        for work_id in tasks:
            # TODO: Resolving one handle_events here can block resolution of
            # other tasks
            try:
                teardown = await asyncio.wait_for(tasks[work_id], DEFAULT_TIMEOUT)
                if teardown:
                    self.cleanup(work_id)
            except asyncio.TimeoutError:
                self.cleanup(work_id)

    def accept_client(self) -> None:
        addr = self.client_queue.recv()
        fileno = recv_handle(self.client_queue)
        self.works[fileno] = self.work_klass(
            fileno=fileno,
            addr=addr,
            flags=self.flags,
            event_queue=self.event_queue
        )
        self.works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__
        )
        try:
            self.works[fileno].initialize()
            os.close(fileno)
        except ssl.SSLError as e:
            logger.exception('ssl.SSLError', exc_info=e)
            self.cleanup(fileno)

    def cleanup_inactive(self) -> None:
        inactive_works: List[int] = []
        for work_id in self.works:
            if self.works[work_id].is_inactive():
                inactive_works.append(work_id)
        for work_id in inactive_works:
            self.cleanup(work_id)

    def cleanup(self, work_id: int) -> None:
        # TODO: HttpProtocolHandler.shutdown can call flush which may block
        self.works[work_id].shutdown()
        del self.works[work_id]

    def run_once(self) -> None:
        assert self.loop is not None
        with self.selected_events() as (readables, writables):
            if len(readables) == 0 and len(writables) == 0:
                # Remove and shutdown inactive connections
                self.cleanup_inactive()
                return
        # Note that selector from now on is idle,
        # until all the logic below completes.
        #
        # Invoke Threadless.handle_events
        # TODO: Only send readable / writables that client originally
        # registered.
        tasks = {}
        for fileno in self.works:
            tasks[fileno] = self.loop.create_task(
                self.handle_events(fileno, readables, writables))
        # Accepted client connection from Acceptor
        if self.client_queue in readables:
            self.accept_client()
        # Wait for Threadless.handle_events to complete
        self.loop.run_until_complete(self.wait_for_tasks(tasks))
        # Remove and shutdown inactive connections
        self.cleanup_inactive()

    def run(self) -> None:
        try:
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.client_queue, selectors.EVENT_READ)
            self.loop = asyncio.get_event_loop()
            while True:
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            assert self.selector is not None
            self.selector.unregister(self.client_queue)
            self.client_queue.close()
            assert self.loop is not None
            self.loop.close()


class Acceptor(multiprocessing.Process):
    """Socket client acceptor.

    Accepts client connection over received server socket handle and
    starts a new work thread.
    """

    lock = multiprocessing.Manager().Lock()

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

        self.running = False
        self.selector: Optional[selectors.DefaultSelector] = None
        self.sock: Optional[socket.socket] = None
        self.threadless_process: Optional[multiprocessing.Process] = None
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
        self.start_work(conn, addr)
        # logger.info('work started in %f seconds', time.time() - now)

    def run(self) -> None:
        self.running = True
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
            while self.running:
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            self.selector.unregister(self.sock)
            if self.flags.threadless:
                self.shutdown_threadless_process()
            self.sock.close()
            self.running = False
