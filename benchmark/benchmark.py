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
import time
from typing import List, Tuple

from proxy.common.constants import __homepage__, DEFAULT_BUFFER_SIZE
from proxy.common.utils import build_http_request
from proxy.http_methods import httpMethods
from proxy.http_parser import httpParserStates, httpParserTypes, HttpParser

DEFAULT_N = 1


def init_parser() -> argparse.ArgumentParser:
    """Initializes and returns argument parser."""
    parser = argparse.ArgumentParser(
        description='Benchmark opens N concurrent connections '
                    'to proxy.py web server. Currently, HTTP/1.1 '
                    'keep-alive connections are opened. Over each opened '
                    'connection multiple pipelined request / response '
                    'packets are exchanged with proxy.py web server.',
        epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__
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

    @staticmethod
    async def send(writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                writer.write(build_http_request(
                    httpMethods.GET, b'/'
                ))
                await asyncio.sleep(0.01)
        except KeyboardInterrupt:
            pass

    @staticmethod
    def parse_pipeline_response(response: HttpParser, raw: bytes, counter: int = 0) -> \
            Tuple[HttpParser, int]:
        response.parse(raw)
        if response.state != httpParserStates.COMPLETE:
            # Need more data
            return response, counter

        if response.buffer == b'':
            # No more buffer left to parse
            return response, counter + 1

        # For pipelined requests we may have pending buffer, try parse them as responses
        pipelined_response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        return Benchmark.parse_pipeline_response(pipelined_response, response.buffer, counter + 1)

    @staticmethod
    async def recv(idd: int, reader: asyncio.StreamReader) -> None:
        print_every = 1000
        last_print = time.time()
        num_completed_requests: int = 0
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        try:
            while True:
                raw = await reader.read(DEFAULT_BUFFER_SIZE)
                response, total_parsed = Benchmark.parse_pipeline_response(response, raw)
                if response.state == httpParserStates.COMPLETE:
                    response = HttpParser(httpParserTypes.RESPONSE_PARSER)
                if total_parsed > 0:
                    num_completed_requests += total_parsed
                    # print('total parsed %d' % total_parsed)
                    if num_completed_requests % print_every == 0:
                        now = time.time()
                        print('[%d] Completed last %d requests in %.2f secs' %
                              (idd, print_every, now - last_print))
                        last_print = now
        except KeyboardInterrupt:
            pass

    async def close_connections(self) -> None:
        for reader, writer in self.clients:
            writer.close()
            await writer.wait_closed()
        print('Closed ' + str(self.n) + ' connections')

    async def run(self) -> None:
        try:
            await self.open_connections()
            print('Exchanging request / response packets')
            readers = []
            writers = []
            idd = 0
            for reader, writer in self.clients:
                readers.append(
                    asyncio.create_task(
                        self.recv(idd, reader)
                    )
                )
                writers.append(
                    asyncio.create_task(
                        self.send(writer)
                    )
                )
                idd += 1
            await asyncio.gather(*(readers + writers))
        finally:
            try:
                await self.close_connections()
            except RuntimeError:
                pass


def main(input_args: List[str]) -> None:
    args = init_parser().parse_args(input_args)
    benchmark = Benchmark(n=args.n)
    try:
        asyncio.run(benchmark.run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main(sys.argv[1:])  # pragma: no cover
