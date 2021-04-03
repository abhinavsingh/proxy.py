# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import NamedTuple, Tuple, List, Optional

from ..common.utils import bytes_, find_http_line
from ..common.constants import CRLF, DEFAULT_BUFFER_SIZE


ChunkParserStates = NamedTuple('ChunkParserStates', [
    ('WAITING_FOR_SIZE', int),
    ('WAITING_FOR_DATA', int),
    ('COMPLETE', int),
])
chunkParserStates = ChunkParserStates(1, 2, 3)


class ChunkParser:
    """HTTP chunked encoding response parser."""

    def __init__(self) -> None:
        self.state = chunkParserStates.WAITING_FOR_SIZE
        self.body: bytes = b''  # Parsed chunks
        self.chunk: bytes = b''  # Partial chunk received
        # Expected size of next following chunk
        self.size: Optional[int] = None

    def parse(self, raw: bytes) -> bytes:
        more = len(raw) > 0
        while more and self.state != chunkParserStates.COMPLETE:
            more, raw = self.process(raw)
        return raw

    def process(self, raw: bytes) -> Tuple[bool, bytes]:
        if self.state == chunkParserStates.WAITING_FOR_SIZE:
            # Consume prior chunk in buffer
            # in case chunk size without CRLF was received
            raw = self.chunk + raw
            self.chunk = b''
            # Extract following chunk data size
            line, raw = find_http_line(raw)
            # CRLF not received or Blank line was received.
            if line is None or line.strip() == b'':
                self.chunk = raw
                raw = b''
            else:
                self.size = int(line, 16)
                self.state = chunkParserStates.WAITING_FOR_DATA
        elif self.state == chunkParserStates.WAITING_FOR_DATA:
            assert self.size is not None
            remaining = self.size - len(self.chunk)
            self.chunk += raw[:remaining]
            raw = raw[remaining:]
            if len(self.chunk) == self.size:
                raw = raw[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = chunkParserStates.COMPLETE
                else:
                    self.state = chunkParserStates.WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(raw) > 0, raw

    @staticmethod
    def to_chunks(raw: bytes, chunk_size: int = DEFAULT_BUFFER_SIZE) -> bytes:
        chunks: List[bytes] = []
        for i in range(0, len(raw), chunk_size):
            chunk = raw[i: i + chunk_size]
            chunks.append(bytes_('{:x}'.format(len(chunk))))
            chunks.append(chunk)
        chunks.append(bytes_('{:x}'.format(0)))
        chunks.append(b'')
        return CRLF.join(chunks) + CRLF
