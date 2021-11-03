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
    """Core event subscriber."""

    def __init__(self, event_queue: EventQueue) -> None:
        self.manager = multiprocessing.Manager()
        self.event_queue = event_queue
        self.relay_thread: Optional[threading.Thread] = None
        self.relay_shutdown: Optional[threading.Event] = None
        self.relay_channel: Optional[DictQueueType] = None
        self.relay_sub_id: Optional[str] = None

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.relay_shutdown = threading.Event()
        self.relay_channel = self.manager.Queue()
        self.relay_thread = threading.Thread(
            target=self.relay,
            args=(self.relay_shutdown, self.relay_channel, callback))
        self.relay_thread.start()
        self.relay_sub_id = uuid.uuid4().hex
        self.event_queue.subscribe(self.relay_sub_id, self.relay_channel)
        logger.debug(
            'Subscribed relay sub id %s from core events',
            self.relay_sub_id)

    def unsubscribe(self) -> None:
        if self.relay_sub_id is None:
            logger.warning('Unsubscribe called without existing subscription')
            return

        assert self.relay_thread
        assert self.relay_shutdown
        assert self.relay_channel
        assert self.relay_sub_id

        try:
            self.event_queue.unsubscribe(self.relay_sub_id)
        except (BrokenPipeError, EOFError):
            pass
        self.relay_shutdown.set()
        self.relay_thread.join()
        logger.debug(
            'Un-subscribed relay sub id %s from core events',
            self.relay_sub_id)

        self.relay_thread = None
        self.relay_shutdown = None
        self.relay_channel = None
        self.relay_sub_id = None

    @staticmethod
    def relay(
            shutdown: threading.Event,
            channel: DictQueueType,
            callback: Callable[[Dict[str, Any]], None]) -> None:
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
