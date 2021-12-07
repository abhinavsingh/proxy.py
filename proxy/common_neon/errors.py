from enum import Enum


class EthereumError(Exception):
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data

    def getError(self):
        error = {'code': self.code, 'message': self.message}
        if self.data: error['data'] = self.data
        return error


class SolanaErrors(Enum):
    AccountNotFound = "Invalid param: could not find account"


class SolanaAccountNotFoundError(Exception):
    """Provides special error processing"""
    def __init__(self):
        super().__init__(SolanaErrors.AccountNotFound.value)
