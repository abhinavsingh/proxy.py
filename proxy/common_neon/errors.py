from enum import Enum


class SolanaErrors(Enum):
    AccountNotFound = "Invalid param: could not find account"


class SolanaAccountNotFoundError(Exception):
    """Provides special error processing"""
    def __init__(self):
        super().__init__(SolanaErrors.AccountNotFound.value)
