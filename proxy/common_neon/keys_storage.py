import os
from typing import Optional
from proxy.common_neon.address import EthereumAddress


class KeyStorage:
    def __init__(self):
        self._key_list = set()
        storage_path = self.storage_path()
        if not os.path.isfile(storage_path):
            return

        with open(storage_path, mode='r') as f:
            line_list = f.readlines()
            for line in line_list:
                pk_key_str = line.strip().lower()
                try:
                    pk_key_data = bytes.fromhex(pk_key_str)
                    EthereumAddress.from_private_key(pk_key_data)
                    self._key_list.add(pk_key_str)
                except:
                    pass

    @staticmethod
    def storage_path() -> os.path:
        dir = os.path.join(os.path.expanduser('~'), '.neon')
        if not os.path.isdir(dir):
            os.mkdir(dir)
        return os.path.join(dir, 'accounts.dat')

    def _save_to_file(self):
        with open(self.storage_path(), mode='w') as f:
            f.truncate()
            for pk_key_str in self._key_list:
                f.write(pk_key_str)
                f.write('\n')

    def generate_new(self) -> EthereumAddress:
        new_address = EthereumAddress.random()
        self._key_list.add(new_address.private.to_hex()[2:])
        self._save_to_file()
        return new_address

    def import_private_key(self, pk_key) -> EthereumAddress:
        new_address = EthereumAddress.from_private_key(pk_key)
        self._key_list.add(new_address.private.to_hex()[2:])
        self._save_to_file()
        return new_address

    def get_list(self) -> [EthereumAddress]:
        return [EthereumAddress.from_private_key(bytes.fromhex(p)) for p in self._key_list]

    def get_key(self, address: str) -> Optional[EthereumAddress]:
        if not isinstance(address, str):
            return None

        address = address.lower()
        account_list = self.get_list()
        for account in account_list:
            if str(account) == address:
                return account
        return None

