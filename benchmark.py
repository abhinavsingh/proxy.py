#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse
import asyncio
import sys
from typing import List, Tuple

import proxy

DEFAULT_N = 1


def init_parser() -> argparse.ArgumentParser:
    """Initializes and returns argument parser."""
    parser = argparse.ArgumentParser(
        description='Benchmark opens N concurrent connections '
                    'to proxy.py web server. Currently, HTTP/1.1 '
                    'keep-alive connections are opened. Over each opened '
                    'connection multiple pipelined request / response '
                    'packets are exchanged with proxy.py web server.',
        epilog='Proxy.py not working? Report at: %s/issues/new' % proxy.__homepage__
    )
    parser.add_argument(
        '--n', '-n',
        type=int,
        default=DEFAULT_N,
        help='Default: ' + str(DEFAULT_N) + '.  See description above for meaning of N.'
    )
    return parser


class Benchmark:

    def __init__(self, n: int = DEFAULT_N) -> None:
        self.n = n
        self.clients: List[Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []

    async def open_connections(self) -> None:
        for _ in range(self.n):
            self.clients.append(await asyncio.open_connection('::', 8899))
        print('Opened ' + str(self.n) + ' connections')

    def send_requests(self) -> None:
        for _, writer in self.clients:
            writer.write(proxy.build_http_request(
                proxy.httpMethods.GET, b'/'
            ))

    async def recv_responses(self) -> None:
        for reader, _ in self.clients:
            response = proxy.HttpParser(proxy.httpParserTypes.RESPONSE_PARSER)
            while response.state != proxy.httpParserStates.COMPLETE:
                response.parse(await reader.read(proxy.DEFAULT_BUFFER_SIZE))

    async def close_connections(self) -> None:
        for reader, writer in self.clients:
            writer.close()
            await writer.wait_closed()
        print('Closed ' + str(self.n) + ' connections')

    async def run(self) -> None:
        num_completed_requests_per_connection: int = 0
        try:
            await self.open_connections()
            print('Exchanging request / response packets')
            while True:
                self.send_requests()
                await self.recv_responses()
                num_completed_requests_per_connection += 1
                await asyncio.sleep(0.1)
        finally:
            await self.close_connections()
            print('Exchanged ' + str(num_completed_requests_per_connection) +
                  ' request / response per connection')


def main(input_args: List[str]) -> None:
    args = init_parser().parse_args(input_args)
    benchmark = Benchmark(n=args.n)
    try:
        asyncio.run(benchmark.run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main(sys.argv[1:])  # pragma: no cover
