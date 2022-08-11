from abc import ABC, abstractmethod

from ..common_neon.data import NeonTxStatData


class IIndexerStatExporter(ABC):

    @abstractmethod
    def on_neon_tx_result(self, result: NeonTxStatData):
        """On Neon transaction result """

    @abstractmethod
    def on_solana_rpc_status(self, status):
        """On Solana status"""

    @abstractmethod
    def on_db_status(self, status):
        """On Neon database status"""
