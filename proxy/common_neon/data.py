from dataclasses import dataclass, field
from typing import List, Optional


class NeonTxStatData:
    def __init__(self, neon_tx_hash: str, neon_income: int, tx_type: str, is_canceled: bool) -> None:
        self.neon_tx_hash = neon_tx_hash
        self.neon_income = neon_income
        self.tx_type = tx_type
        self.is_canceled = is_canceled
        self.instructions = []

    def add_instruction(self, sol_tx_hash: str, sol_spent: int, steps: int, bpf: int) -> None:
        self.instructions.append((sol_tx_hash, sol_spent, steps, bpf))


@dataclass
class NeonTxReturn:
    exit_status: int = 0
    gas_used: int = 0
    return_value: Optional[bytes] = None


@dataclass
class NeonEvent:
    address: Optional[bytes] = None
    count_topics: int = 0
    topics: Optional[List[bytes]] = None
    log_data: Optional[bytes] = None


@dataclass
class NeonLogIx:
    neon_return: Optional[NeonTxReturn] = None
    neon_events: List[NeonEvent] = field(default_factory=list)
