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
import time
import multiprocessing
import logging

from typing import Dict, Any, Optional

from proxy.common.constants import DEFAULT_LOG_FORMAT
from proxy.core.event import EventManager, EventQueue, EventSubscriber, eventNames

logging.basicConfig(level=logging.DEBUG, format=DEFAULT_LOG_FORMAT)

logger = logging.getLogger(__name__)


num_events_received = [0, 0]


# Execute within a separate thread context
def on_event(payload: Dict[str, Any]) -> None:
    '''Subscriber callback.'''
    global num_events_received
    if payload['request_id'] == '1234':
        num_events_received[0] += 1
    else:
        num_events_received[1] += 1


def publisher_process(
    shutdown_event: multiprocessing.synchronize.Event,
    dispatcher_queue: EventQueue,
) -> None:
    logger.info('publisher started')
    try:
        while not shutdown_event.is_set():
            dispatcher_queue.publish(
                request_id='12345',
                event_name=eventNames.WORK_STARTED,
                event_payload={'time': time.time()},
                publisher_id='eventing_pubsub_process',
            )
    except KeyboardInterrupt:
        pass
    logger.info('publisher shutdown')


if __name__ == '__main__':
    start_time = time.time()

    # Start eventing core
    subscriber: Optional[EventSubscriber] = None
    with EventManager() as event_manager:
        assert event_manager.queue

        # Create a subscriber.
        # Internally, subscribe will start a separate thread
        # to receive incoming published messages.
        subscriber = EventSubscriber(event_manager.queue, callback=on_event)
        subscriber.setup()

        # Start a publisher process to demonstrate safe exchange
        # of messages between processes.
        publisher_shutdown_event = multiprocessing.Event()
        publisher = multiprocessing.Process(
            target=publisher_process, args=(
                publisher_shutdown_event, event_manager.queue, ),
        )
        publisher.start()

        # Dispatch event from main process too
        # to demonstrate safe exchange of messages
        # between threads.
        try:
            while True:
                event_manager.queue.publish(
                    request_id='1234',
                    event_name=eventNames.WORK_STARTED,
                    event_payload={'time': time.time()},
                    publisher_id='eventing_pubsub_main',
                )
        except KeyboardInterrupt:
            logger.info('bye!!!')
        finally:
            # Stop publisher process
            publisher_shutdown_event.set()
            publisher.join()
            # Stop subscriber thread
            subscriber.unsubscribe()
            logger.info(
                'Received {0} events from main thread, {1} events from another process, in {2} seconds'.format(
                    num_events_received[0], num_events_received[1], time.time(
                    ) - start_time,
                ),
            )
    if subscriber:
        subscriber.shutdown(do_unsubscribe=False)
