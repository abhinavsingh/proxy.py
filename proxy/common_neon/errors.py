class EthereumError(Exception):
    def __init__(self, message, code=-32000, data=None):
        self.code = code
        self.message = message
        self.data = data

    def getError(self):
        error = {'code': self.code, 'message': self.message}
        if self.data: error['data'] = self.data
        return error


class PendingTxError(Exception):
    pass
