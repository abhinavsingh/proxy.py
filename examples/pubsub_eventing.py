# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import threading
import multiprocessing
import logging

from typing import Dict, Any

from proxy.core.event import EventQueue, EventSubscriber, EventDispatcher, eventNames

# Enable debug logging to view core event logs
logging.basicConfig(level=logging.DEBUG)

# Eventing requires a multiprocess safe queue
# so that events can be safely published and received
# between processes.
manager = multiprocessing.Manager()

main_publisher_request_id = '1234'
process_publisher_request_id = '12345'
num_events_received = [0, 0]


def publisher_process(shutdown_event: multiprocessing.synchronize.Event,
                      dispatcher_queue: EventQueue) -> None:
    print('publisher starting')
    try:
        while not shutdown_event.is_set():
            dispatcher_queue.publish(
                request_id='12345',
                event_name=eventNames.WORK_STARTED,
                event_payload={'time': time.time()},
                publisher_id='eventing_pubsub_process'
            )
    except KeyboardInterrupt:
        pass
    print('publisher shutdown')


def on_event(payload: Dict[str, Any]) -> None:
    '''Subscriber callback.'''
    global num_events_received
    if payload['request_id'] == main_publisher_request_id:
        num_events_received[0] += 1
    else:
        num_events_received[1] += 1
    # print(payload)


if __name__ == '__main__':
    start_time = time.time()

    # Start dispatcher thread
    dispatcher_queue = EventQueue(manager.Queue())
    dispatcher_shutdown_event = threading.Event()
    dispatcher = EventDispatcher(
        shutdown=dispatcher_shutdown_event,
        event_queue=dispatcher_queue)
    dispatcher_thread = threading.Thread(target=dispatcher.run)
    dispatcher_thread.start()

    # Create a subscriber
    subscriber = EventSubscriber(dispatcher_queue)
    # Internally, subscribe will start a separate thread
    # to receive incoming published messages
    subscriber.subscribe(on_event)

    # Start a publisher process to demonstrate safe exchange
    # of messages between processes.
    publisher_shutdown_event = multiprocessing.Event()
    publisher = multiprocessing.Process(
        target=publisher_process, args=(
            publisher_shutdown_event, dispatcher_queue, ))
    publisher.start()

    try:
        while True:
            # Dispatch event from main process
            dispatcher_queue.publish(
                request_id='1234',
                event_name=eventNames.WORK_STARTED,
                event_payload={'time': time.time()},
                publisher_id='eventing_pubsub_main'
            )
    except KeyboardInterrupt:
        print('bye!!!')
    finally:
        # Stop publisher
        publisher_shutdown_event.set()
        publisher.join()
        # Stop subscriber thread
        subscriber.unsubscribe()
        # Signal dispatcher to shutdown
        dispatcher_shutdown_event.set()
        # Wait for dispatcher shutdown
        dispatcher_thread.join()
    print('Received {0} events from main thread, {1} events from another process, in {2} seconds'.format(
        num_events_received[0], num_events_received[1], time.time() - start_time))
