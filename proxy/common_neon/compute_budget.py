from solana.transaction import TransactionInstruction, Transaction
from .constants import COMPUTE_BUDGET_ID

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

DEFAULT_UNITS=500*1000
DEFAULT_HEAP_FRAME=256*1024
DEFAULT_ADDITIONAL_FEE=0

def TransactionWithComputeBudget(units=DEFAULT_UNITS, additional_fee=DEFAULT_ADDITIONAL_FEE, heapFrame=DEFAULT_HEAP_FRAME, **args):
    trx = Transaction(**args)
    if units: trx.add(ComputeBudget.requestUnits(units, additional_fee))
    if heapFrame: trx.add(ComputeBudget.requestHeapFrame(heapFrame))
    return trx
