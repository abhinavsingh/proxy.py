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

    def __init__(self, event_queue: EventQueue, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.event_queue = event_queue
        self.callback = callback
        self.relay_thread: Optional[threading.Thread] = None
        self.relay_shutdown: Optional[threading.Event] = None
        self.relay_recv: Optional[connection.Connection] = None
        self.relay_send: Optional[connection.Connection] = None
        self.relay_sub_id: Optional[str] = None

    def __enter__(self) -> 'EventSubscriber':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def setup(self, do_subscribe: bool = True) -> None:
        """Setup subscription thread.

        Call subscribe() to actually start subscription.
        """
        self._start_relay_thread()
        assert self.relay_sub_id and self.relay_recv
        logger.debug(
            'Subscriber#%s relay setup done',
            self.relay_sub_id,
        )
        if do_subscribe:
            self.subscribe()

    def shutdown(self, do_unsubscribe: bool = True) -> None:
        """Tear down subscription thread.

        Call unsubscribe() to actually stop subscription.
        """
        self._stop_relay_thread()
        logger.debug(
            'Subscriber#%s relay shutdown done',
            self.relay_sub_id,
        )
        if do_unsubscribe:
            self.unsubscribe()

    def subscribe(self) -> None:
        assert self.relay_sub_id and self.relay_send
        self.event_queue.subscribe(self.relay_sub_id, self.relay_send)

    def unsubscribe(self) -> None:
        if self.relay_sub_id is None:
            logger.warning(
                'Relay called unsubscribe without an active subscription',
            )
            return
        try:
            self.event_queue.unsubscribe(self.relay_sub_id)
        except BrokenPipeError:
            pass
        except EOFError:
            pass
        finally:
            # self.relay_sub_id = None
            pass

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
                        logger.info(
                            'Subscriber#{0} subscribe ack received'.format(
                                sub_id,
                            ),
                        )
                    elif ev['event_name'] == eventNames.UNSUBSCRIBED:
                        logger.info(
                            'Subscriber#{0} unsubscribe ack received'.format(
                                sub_id,
                            ),
                        )
                        break
                    elif ev['event_name'] == eventNames.DISPATCHER_SHUTDOWN:
                        logger.info(
                            'Subscriber#{0} received dispatcher shutdown event'.format(
                                sub_id,
                            ),
                        )
                        break
                    else:
                        callback(ev)
            except queue.Empty:
                pass
            except EOFError:
                break
            except KeyboardInterrupt:
                break

    def _start_relay_thread(self) -> None:
        self.relay_sub_id = uuid.uuid4().hex
        self.relay_shutdown = threading.Event()
        self.relay_recv, self.relay_send = multiprocessing.Pipe()
        self.relay_thread = threading.Thread(
            target=EventSubscriber.relay,
            args=(
                self.relay_sub_id, self.relay_shutdown,
                self.relay_recv, self.callback,
            ),
        )
        self.relay_thread.daemon = True
        self.relay_thread.start()

    def _stop_relay_thread(self) -> None:
        assert self.relay_thread and self.relay_shutdown and self.relay_recv and self.relay_send
        self.relay_shutdown.set()
        self.relay_thread.join()
        self.relay_recv.close()
        # Currently relay_send instance here in
        # subscriber is not the same as one received
        # by dispatcher.  This may cause file
        # descriptor leakage.  So we make a close
        # here explicit on our side of relay_send too.
        self.relay_send.close()
        self.relay_thread = None
        self.relay_shutdown = None
        self.relay_recv = None
        self.relay_send = None
