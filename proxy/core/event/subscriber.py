# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import queue
import threading
import multiprocessing
import logging
import uuid

from typing import Dict, Optional, Any, Callable

from ...common.types import DictQueueType

from .queue import EventQueue

logger = logging.getLogger(__name__)


class EventSubscriber:
    """Core event subscriber.

    EventSubscriber can run in a thread or process which is
    different from publisher(s).  Note that, EventSubscriber
    cannot share the `multiprocessing.Manager` with the
    EventManager because EventSubscriber can be started
    in a different process.  Manager is used to initialize
    a new Queue which is used for subscriptions (and must
    be multiprocess safe queue).

    When `subscribe` method is called, EventManager will:

    1) Start a relay thread which consumes from the channel
       passed to the relay thread.
    2)
    """

    def __init__(self, event_queue: EventQueue) -> None:
        self.manager: Optional[multiprocessing.managers.SyncManager] = multiprocessing.Manager(
        )
        self.event_queue = event_queue
        self.relay_thread: Optional[threading.Thread] = None
        self.relay_shutdown: Optional[threading.Event] = None
        self.relay_channel: Optional[DictQueueType] = None
        self.relay_sub_id: Optional[str] = None

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self._start_relay_thread(callback)
        assert self.relay_sub_id and self.relay_channel
        self.event_queue.subscribe(self.relay_sub_id, self.relay_channel)
        logger.debug(
            'Subscribed relay sub id %s from core events',
            self.relay_sub_id,
        )

    def unsubscribe(self) -> None:
        if self.relay_sub_id is None:
            logger.warning('Unsubscribe called without existing subscription')
            return

        try:
            self.event_queue.unsubscribe(self.relay_sub_id)
        except BrokenPipeError:
            pass
        except EOFError:
            pass

        self._stop_relay_thread()
        logger.debug(
            'Un-subscribed relay sub id %s from core events',
            self.relay_sub_id,
        )

    @staticmethod
    def relay(
            shutdown: threading.Event,
            channel: DictQueueType,
            callback: Callable[[Dict[str, Any]], None],
    ) -> None:
        while not shutdown.is_set():
            try:
                ev = channel.get(timeout=1)
                callback(ev)
            except queue.Empty:
                pass
            except EOFError:
                break
            except KeyboardInterrupt:
                break

    def _start_relay_thread(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        # self.manager = multiprocessing.Manager()
        self.relay_sub_id = uuid.uuid4().hex
        self.relay_shutdown = threading.Event()
        self.relay_channel = self.manager.Queue()
        self.relay_thread = threading.Thread(
            target=EventSubscriber.relay,
            args=(self.relay_shutdown, self.relay_channel, callback),
        )
        self.relay_thread.start()

    def _stop_relay_thread(self) -> None:
        assert self.manager and self.relay_thread and self.relay_shutdown and self.relay_channel and self.relay_sub_id
        self.relay_shutdown.set()
        self.relay_thread.join()
        self.manager.shutdown()
        self.relay_thread, self.relay_shutdown, self.relay_channel, self.relay_sub_id, self.manager = None, None, None, None, None
