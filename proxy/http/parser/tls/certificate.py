from typing import Optional, Tuple


class TlsCertificate:
    """TLS Certificate"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        self.data = raw
        return True, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsCertificateRequest:
    """TLS Certificate Request"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsCertificateVerify:
    """TLS Certificate Verify"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data
