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
from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID
from ....http.parser import HttpParser


class CacheStore(ABC):

    def __init__(self, uid: UUID) -> None:
        self.uid = uid

    @abstractmethod
    def open(self, request: HttpParser) -> None:
        pass

    @abstractmethod
    def cache_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    @abstractmethod
    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    @abstractmethod
    def close(self) -> None:
        pass
