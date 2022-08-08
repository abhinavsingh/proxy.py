from abc import ABC, abstractmethod
from typing import Optional
from solana.publickey import PublicKey
import os


class IConfig(ABC):

    @abstractmethod
    def get_solana_url(self) -> str:
        """Gets the predefinded solana url"""

    @abstractmethod
    def get_evm_steps_limit(self) -> int:
        """Gets the evm steps limitation, that is used to check steps gotten over emulating"""

    @abstractmethod
    def get_mempool_capacity(self) -> int:
        """Gets the capacity of the MemPool schedule to constrain the transactions count in there"""

    @abstractmethod
    def get_pyth_mapping_account(self) -> Optional[str]:
        """Gets pyth network account to retrieve gas price from there"""

    @abstractmethod
    def get_pyth_solana_url(self) -> str:
        """Gets solana url for GasPriceCalculator in test purposes"""


class Config(IConfig):

    def get_solana_url(self) -> str:
        return os.environ.get("SOLANA_URL", "http://localhost:8899")

    def get_evm_steps_limit(self) -> int:
        return int(os.environ.get("EVM_STEP_COUNT", 750))

    def get_mempool_capacity(self) -> int:
        return int(os.environ.get("MEMPOOL_CAPACITY", 4096))

    def get_pyth_mapping_account(self) -> Optional[str]:
        pyth_mapping_account = os.environ.get("PYTH_MAPPING_ACCOUNT")
        if pyth_mapping_account is not None:
            pyth_mapping_account = PublicKey(pyth_mapping_account)
        return pyth_mapping_account

    def get_pyth_solana_url(self) -> str:
        solana_url = os.environ.get("PP_SOLANA_URL")
        return solana_url if solana_url is not None else self.get_solana_url()

    def __str__(self):
        return f"\n" \
               f"        SOLANA_URL: {self.get_solana_url()}, \n" \
               f"        PP_SOLANA_URL: {self.get_pyth_solana_url()}\n" \
               f"        PYTH_MAPPING_ACCOUNT: {self.get_pyth_mapping_account()}\n" \
               f"        EVM_STEP_LIMIT: {self.get_evm_steps_limit()}, \n" \
               f"        MP_CAPACITY: {self.get_mempool_capacity()}\n" \
               f"        "
