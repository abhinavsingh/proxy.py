# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import time
from typing import Any, Dict

from ..websocket import WebsocketFrame
from ...common.constants import PROXY_PY_START_TIME, DEFAULT_DEVTOOLS_DOC_URL
from ...common.constants import DEFAULT_DEVTOOLS_FRAME_ID, DEFAULT_DEVTOOLS_LOADER_ID
from ...common.utils import bytes_
from ...core.connection import TcpClientConnection
from ...core.event import eventNames


class CoreEventsToDevtoolsProtocol:
    """Open in Chrome

    devtools://devtools/bundled/inspector.html?ws=localhost:8899/devtools
    """

    RESPONSES: Dict[str, bytes] = {}

    @staticmethod
    def transformer(
        client: TcpClientConnection,
        event: Dict[str, Any],
    ) -> None:
        event_name = event['event_name']
        if event_name == eventNames.REQUEST_COMPLETE:
            data = CoreEventsToDevtoolsProtocol.request_complete(event)
        elif event_name == eventNames.RESPONSE_HEADERS_COMPLETE:
            data = CoreEventsToDevtoolsProtocol.response_headers_complete(
                event,
            )
        elif event_name == eventNames.RESPONSE_CHUNK_RECEIVED:
            data = CoreEventsToDevtoolsProtocol.response_chunk_received(event)
        elif event_name == eventNames.RESPONSE_COMPLETE:
            data = CoreEventsToDevtoolsProtocol.response_complete(event)
        else:
            # drop core events unrelated to Devtools
            return
        client.queue(
            memoryview(
                WebsocketFrame.text(
                    bytes_(
                        json.dumps(data),
                    ),
                ),
            ),
        )

    @staticmethod
    def request_complete(event: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        return {
            'method': 'Network.requestWillBeSent',
            'params': {
                'requestId': event['request_id'],
                'frameId': DEFAULT_DEVTOOLS_FRAME_ID,
                'loaderId': DEFAULT_DEVTOOLS_LOADER_ID,
                'documentURL': DEFAULT_DEVTOOLS_DOC_URL,
                'timestamp': now - PROXY_PY_START_TIME,
                'wallTime': now,
                'hasUserGesture': False,
                'type': event['event_payload']['headers']['content-type']
                if 'content-type' in event['event_payload']['headers']
                else 'Other',
                'request': {
                    'url': event['event_payload']['url'],
                    'method': event['event_payload']['method'],
                    'headers': event['event_payload']['headers'],
                    'postData': event['event_payload']['body'],
                    'initialPriority': 'High',
                    'urlFragment': '',
                    'mixedContentType': 'none',
                },
                'initiator': {
                    'type': 'other',
                },
            },
        }

    @staticmethod
    def response_headers_complete(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'method': 'Network.responseReceived',
            'params': {
                'requestId': event['request_id'],
                'frameId': DEFAULT_DEVTOOLS_FRAME_ID,
                'loaderId': DEFAULT_DEVTOOLS_LOADER_ID,
                'timestamp': time.time(),
                'type': event['event_payload']['headers']['content-type']
                if event['event_payload']['headers'].has_header('content-type')
                else 'Other',
                'response': {
                    'url': '',
                    'status': '',
                    'statusText': '',
                    'headers': '',
                    'headersText': '',
                    'mimeType': '',
                    'connectionReused': True,
                    'connectionId': '',
                    'encodedDataLength': '',
                    'fromDiskCache': False,
                    'fromServiceWorker': False,
                    'timing': {
                        'requestTime': '',
                        'proxyStart': -1,
                        'proxyEnd': -1,
                        'dnsStart': -1,
                        'dnsEnd': -1,
                        'connectStart': -1,
                        'connectEnd': -1,
                        'sslStart': -1,
                        'sslEnd': -1,
                        'workerStart': -1,
                        'workerReady': -1,
                        'sendStart': 0,
                        'sendEnd': 0,
                        'receiveHeadersEnd': 0,
                    },
                    'requestHeaders': '',
                    'remoteIPAddress': '',
                    'remotePort': '',
                },
            },
        }

    @staticmethod
    def response_chunk_received(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'method': 'Network.dataReceived',
            'params': {
                'requestId': event['request_id'],
                'timestamp': time.time(),
                'dataLength': event['event_payload']['chunk_size'],
                'encodedDataLength': event['event_payload']['encoded_chunk_size'],
            },
        }

    @staticmethod
    def response_complete(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'method': 'Network.loadingFinished',
            'params': {
                'requestId': event['request_id'],
                'timestamp': time.time(),
                'encodedDataLength': event['event_payload']['encoded_response_size'],
                'shouldReportCorbBlocking': False,
            },
        }
