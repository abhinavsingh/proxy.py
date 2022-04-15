from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any


class Result:
    def __init__(self, reason: str = None):
        self._reason = reason

    def __bool__(self) -> bool:
        return self._reason is None

    def __str__(self) -> str:
        return self._reason if self._reason is not None else ""


@dataclass
class NeonTxPrecheckResult:
    is_underpriced_tx_without_chainid: bool
    emulating_result: NeonEmulatingResult


NeonEmulatingResult = Dict[str, Any]
