# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import uuid
import queue
import logging
import threading
import multiprocessing

from multiprocessing import connection

from typing import Dict, Optional, Any, Callable

from .queue import EventQueue
from .names import eventNames

logger = logging.getLogger(__name__)


class EventSubscriber:
    """Core event subscriber.

    Usage: Initialize one instance per CPU core for optimum performance.

    EventSubscriber can run within various context. E.g. main thread,
    another thread or a different process.  EventSubscriber context
    can be different from publishers.  Publishers can even be processes
    outside of the proxy.py core.

    Note that, EventSubscriber cannot share the `multiprocessing.Manager`
    with the EventManager.  Because EventSubscriber can be started
    in a different process than EventManager.

    `multiprocessing.Manager` is used to initialize
    a new Queue which is used for subscriptions.  EventDispatcher
    might be running in a separate process and hence
    subscription queue must be multiprocess safe.

    When `subscribe` method is called, EventManager will
    start a relay thread which consumes using the multiprocess
    safe queue passed to the relay thread.
    """

    def __init__(self, event_queue: EventQueue) -> None:
        self.event_queue = event_queue
        self.relay_thread: Optional[threading.Thread] = None
        self.relay_shutdown: Optional[threading.Event] = None
        self.relay_recv: Optional[connection.Connection] = None
        self.relay_send: Optional[connection.Connection] = None
        self.relay_sub_id: Optional[str] = None

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self._start_relay_thread(callback)
        assert self.relay_sub_id and self.relay_recv
        logger.debug(
            'Subscriber#%s subscribing',
            self.relay_sub_id,
        )
        self.event_queue.subscribe(self.relay_sub_id, self.relay_send)

    def unsubscribe(self) -> None:
        if self.relay_sub_id is None:
            logger.warning(
                'Relay called unsubscribe without an active subscription')
            return
        logger.debug(
            'Subscriber#%s unsubscribing',
            self.relay_sub_id,
        )
        try:
            self.event_queue.unsubscribe(self.relay_sub_id)
        except BrokenPipeError:
            logger.info('bpe')
            pass
        except EOFError:
            logger.info('eof')
            pass
        finally:
            self._stop_relay_thread()
            # close recv end
            self.relay_recv.close()
            # close send too?
            # dispatcher may also close?
            self.relay_send.close()
            self.relay_recv = None
            self.relay_send = None
            self.relay_sub_id = None

    @staticmethod
    def relay(
            sub_id: str,
            shutdown: threading.Event,
            channel: connection.Connection,
            callback: Callable[[Dict[str, Any]], None],
    ) -> None:
        while not shutdown.is_set():
            try:
                if channel.poll(timeout=1):
                    ev = channel.recv()
                    if ev['event_name'] == eventNames.SUBSCRIBED:
                        logger.info('Subscriber#{0} subscribed'.format(sub_id))
                    elif ev['event_name'] == eventNames.UNSUBSCRIBED:
                        logger.info(
                            'Subscriber#{0} unsubscribed'.format(sub_id))
                        break
                    else:
                        callback(ev)
            except queue.Empty:
                pass
            except EOFError:
                break
            except KeyboardInterrupt:
                print('relay got kbe')
                break

    def _start_relay_thread(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.relay_sub_id = uuid.uuid4().hex
        self.relay_shutdown = threading.Event()
        self.relay_recv, self.relay_send = multiprocessing.Pipe()
        self.relay_thread = threading.Thread(
            target=EventSubscriber.relay,
            args=(self.relay_sub_id, self.relay_shutdown,
                  self.relay_recv, callback),
        )
        self.relay_thread.start()

    def _stop_relay_thread(self) -> None:
        assert self.relay_thread and self.relay_shutdown and self.relay_recv and self.relay_sub_id
        self.relay_shutdown.set()
        self.relay_thread.join()
        logger.info('Relay thread joined')
        self.relay_thread = None
        self.relay_shutdown = None
