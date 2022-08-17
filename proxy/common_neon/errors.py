class EthereumError(Exception):
    def __init__(self, message, code=-32000, data=None):
        self.code = code
        self.message = message
        self.data = data

    def getError(self):
        error = {'code': self.code, 'message': self.message}
        if self.data: error['data'] = self.data
        return error


class InvalidParamError(EthereumError):
    def __init__(self, message, data=None):
        EthereumError.__init__(self, message=message, code=-32602, data=data)


class AddressLookupTableError(RuntimeError):
    def __init__(self, *args) -> None:
        RuntimeError.__init__(self, *args)


class BlockedAccountsError(Exception):
    def __init__(self):
        super().__init__(self)


class NodeBehindError(Exception):
    def __int__(self):
        super().__init__(self)


class SolanaUnavailableError(Exception):
    def __int__(self):
        super().__init__(self)
