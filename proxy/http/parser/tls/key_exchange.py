
from typing import Optional, Tuple


class TlsServerKeyExchange:
    """TLS Server Key Exchange"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        self.data = raw
        return True, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsClientKeyExchange:
    """TLS Client Key Exchange"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data
