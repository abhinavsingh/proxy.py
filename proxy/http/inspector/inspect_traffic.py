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
from typing import TYPE_CHECKING, Any, Dict, List

from proxy.core.event import EventSubscriber
from proxy.common.utils import bytes_
from proxy.http.websocket import WebsocketFrame, WebSocketTransportBasePlugin


if TYPE_CHECKING:   # pragma: no cover
    from ..connection import HttpClientConnection


class InspectTrafficPlugin(WebSocketTransportBasePlugin):
    """Websocket API for inspect_traffic.ts frontend plugin."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.subscriber = EventSubscriber(
            self.event_queue,
            callback=lambda event: InspectTrafficPlugin.callback(
                self.client, event,
            ),
        )

    def methods(self) -> List[str]:
        return [
            'enable_inspection',
            'disable_inspection',
        ]

    def handle_message(self, message: Dict[str, Any]) -> None:
        if message['method'] == 'enable_inspection':
            # inspection can only be enabled if --enable-events is used
            if not self.flags.enable_events:
                self.reply({
                    'id': message['id'],
                    'response': 'not enabled',
                })
            else:
                self.subscriber.setup()
                self.reply(
                    {'id': message['id'], 'response': 'inspection_enabled'},
                )
        elif message['method'] == 'disable_inspection':
            self.subscriber.shutdown()
            self.reply({
                'id': message['id'],
                'response': 'inspection_disabled',
            })
        else:
            raise NotImplementedError()

    @staticmethod
    def callback(client: 'HttpClientConnection', event: Dict[str, Any]) -> None:
        event['push'] = 'inspect_traffic'
        client.queue(
            memoryview(
                WebsocketFrame.text(
                    bytes_(
                        json.dumps(event),
                    ),
                ),
            ),
        )
