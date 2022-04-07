from solana.transaction import TransactionInstruction, Transaction
from .constants import COMPUTE_BUDGET_ID
from ..environment import NEON_HEAP_FRAME, NEON_COMPUTE_UNITS, NEON_ADDITIONAL_FEE

class ComputeBudget():
    @staticmethod
    def requestUnits(units, additional_fee):
        return TransactionInstruction(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("00")+units.to_bytes(4,"little")+additional_fee.to_bytes(4,"little")
        )

    @staticmethod
    def requestHeapFrame(heapFrame):
        return TransactionInstruction(
            program_id=COMPUTE_BUDGET_ID,
            keys=[],
            data=bytes.fromhex("01")+heapFrame.to_bytes(4,"little")
        )


def TransactionWithComputeBudget(units=NEON_COMPUTE_UNITS, additional_fee=NEON_ADDITIONAL_FEE, heapFrame=NEON_HEAP_FRAME, **args):
    trx = Transaction(**args)
    if units: trx.add(ComputeBudget.requestUnits(units, additional_fee))
    if heapFrame: trx.add(ComputeBudget.requestHeapFrame(heapFrame))
    return trx
