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
import logging

from typing import Dict, Any, List

from ...common.types import DictQueueType

from .queue import EventQueue
from .names import eventNames

logger = logging.getLogger(__name__)


class EventDispatcher:
    """Core EventDispatcher.

    Provides:
    1. A dispatcher module which consumes core events and dispatches
       them to EventQueueBasePlugin
    2. A publish utility for publishing core events into
       global events queue.

    Direct consuming from global events queue outside of dispatcher
    module is not-recommended.  Python native multiprocessing queue
    doesn't provide a fanout functionality which core dispatcher module
    implements so that several plugins can consume same published
    event at a time.

    When --enable-events is used, a multiprocessing.Queue is created and
    attached to global argparse.  This queue can then be used for
    dispatching an Event dict object into the queue.

    When --enable-events is used, dispatcher module is automatically
    started. Dispatcher module also ensures that queue is not full and
    doesn't utilize too much memory in case there are no event plugins
    enabled.
    """

    def __init__(
            self,
            shutdown: threading.Event,
            event_queue: EventQueue) -> None:
        self.shutdown: threading.Event = shutdown
        self.event_queue: EventQueue = event_queue
        self.subscribers: Dict[str, DictQueueType] = {}

    def handle_event(self, ev: Dict[str, Any]) -> None:
        if ev['event_name'] == eventNames.SUBSCRIBE:
            self.subscribers[ev['event_payload']['sub_id']] = \
                ev['event_payload']['channel']
        elif ev['event_name'] == eventNames.UNSUBSCRIBE:
            del self.subscribers[ev['event_payload']['sub_id']]
        else:
            # logger.info(ev)
            unsub_ids: List[str] = []
            for sub_id in self.subscribers:
                try:
                    self.subscribers[sub_id].put(ev)
                except BrokenPipeError:
                    unsub_ids.append(sub_id)
            for sub_id in unsub_ids:
                del self.subscribers[sub_id]

    def run_once(self) -> None:
        ev: Dict[str, Any] = self.event_queue.queue.get(timeout=1)
        self.handle_event(ev)

    def run(self) -> None:
        try:
            while not self.shutdown.is_set():
                try:
                    self.run_once()
                except queue.Empty:
                    pass
        except BrokenPipeError:
            pass
        except EOFError:
            pass
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception('Event dispatcher exception', exc_info=e)
