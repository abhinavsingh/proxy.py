# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
import queue
import logging
import threading

from multiprocessing import connection

from typing import Dict, Any, List

from .queue import EventQueue
from .names import eventNames

logger = logging.getLogger(__name__)


class EventDispatcher:
    """Core EventDispatcher.

    Direct consuming from global events queue outside of dispatcher
    module is not-recommended.  Python native multiprocessing queue
    doesn't provide a fanout functionality which core dispatcher module
    implements so that several plugins can consume the same published
    event concurrently (when necessary).

    When --enable-events is used, a multiprocessing.Queue is created and
    attached to global flags.  This queue can then be used for
    dispatching an Event dict object into the queue.

    When --enable-events is used, dispatcher module is automatically
    started.  Most importantly, dispatcher module ensures that queue is
    not flooded and doesn't utilize too much memory in case there are no
    event subscriber is enabled.
    """

    def __init__(
            self,
            shutdown: threading.Event,
            event_queue: EventQueue,
    ) -> None:
        self.shutdown: threading.Event = shutdown
        self.event_queue: EventQueue = event_queue
        # subscriber connection objects
        self.subscribers: Dict[str, connection.Connection] = {}

    def handle_event(self, ev: Dict[str, Any]) -> None:
        if ev['event_name'] == eventNames.SUBSCRIBE:
            self.subscribers[ev['event_payload']['sub_id']] = \
                ev['event_payload']['conn']
            # send ack
            ev['event_payload']['conn'].send({
                'event_name': eventNames.SUBSCRIBED,
            })
        elif ev['event_name'] == eventNames.UNSUBSCRIBE:
            # send ack
            print('unsubscription request ack sent')
            self.subscribers[ev['event_payload']['sub_id']].send({
                'event_name': eventNames.UNSUBSCRIBED,
            })
            # close conn and delete subscriber
            self.subscribers[ev['event_payload']['sub_id']].close()
            del self.subscribers[ev['event_payload']['sub_id']]
        else:
            # logger.info(ev)
            self._broadcast(ev)

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
            logger.exception('Dispatcher exception', exc_info=e)
        finally:
            # Send shutdown message to all active subscribers
            self._broadcast({
                'event_name': eventNames.DISPATCHER_SHUTDOWN,
            })

    def _broadcast(self, ev: Dict[str, Any]) -> None:
        broken_pipes: List[str] = []
        for sub_id in self.subscribers:
            try:
                self.subscribers[sub_id].send(ev)
            except BrokenPipeError:
                logger.warning(
                    'Subscriber#%s broken pipe', sub_id,
                )
                self.subscribers[sub_id].close()
                broken_pipes.append(sub_id)
        for sub_id in broken_pipes:
            del self.subscribers[sub_id]
