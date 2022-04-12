from __future__ import annotations

from solana.transaction import TransactionInstruction, Transaction
from .constants import COMPUTE_BUDGET_ID
from ..environment import NEON_HEAP_FRAME, NEON_COMPUTE_UNITS, NEON_ADDITIONAL_FEE
from typing import Union


class ComputeBudget:
    @staticmethod
    def requestUnits(units, additional_fee) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("00") + units.to_bytes(4, "little") + additional_fee.to_bytes(4, "little")
        )

    @staticmethod
    def requestHeapFrame(heap_frame) -> TransactionInstruction:
        return TransactionInstruction(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("01") + heap_frame.to_bytes(4, "little")
        )


class TransactionWithComputeBudget(Transaction):
    def __init__(self, *args, **kwargs):
        Transaction.__init__(self, *args, **kwargs)
        self.instructions.append(ComputeBudget.requestUnits(NEON_COMPUTE_UNITS, NEON_ADDITIONAL_FEE))
        self.instructions.append(ComputeBudget.requestHeapFrame(NEON_HEAP_FRAME))

    def add(self, *args: Union[Transaction, TransactionInstruction]) -> TransactionWithComputeBudget:
        """Add one or more instructions to this Transaction."""
        for arg in args:
            if isinstance(arg, Transaction):
                for ix in arg.instructions:
                    if ix.program_id == COMPUTE_BUDGET_ID:
                        continue
                    else:
                        self.instructions.append(ix)
            elif isinstance(arg, TransactionInstruction):
                self.instructions.append(arg)
            else:
                raise ValueError("invalid instruction:", arg)

        return self
