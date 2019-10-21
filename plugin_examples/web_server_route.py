"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


class WebServerPlugin(proxy.HttpWebServerBasePlugin):
    """Demonstration of inbuilt web server routing via plugin."""

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (proxy.httpProtocolTypes.HTTP, b'/http-route-example'),
            (proxy.httpProtocolTypes.HTTPS, b'/https-route-example'),
            (proxy.httpProtocolTypes.WEBSOCKET, b'/ws-route-example'),
        ]

    def handle_request(self, request: proxy.HttpParser) -> None:
        if request.path == b'/http-route-example':
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.OK, body=b'HTTP route response'))
        elif request.path == b'/https-route-example':
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.OK, body=b'HTTPS route response'))

    def on_websocket_open(self) -> None:
        proxy.logger.info('Websocket open')

    def on_websocket_message(self, frame: proxy.WebsocketFrame) -> None:
        proxy.logger.info(frame.data)

    def on_websocket_close(self) -> None:
        proxy.logger.info('Websocket close')
