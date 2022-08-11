from abc import ABC, abstractmethod
from decimal import Decimal
from typing import Optional


class StatisticsExporter(ABC):

    @abstractmethod
    def stat_commit_request_and_timeout(self, method: str, latency: float):
        """Request method and its latency"""

    @abstractmethod
    def stat_commit_tx_begin(self):
        """Add started TX"""

    @abstractmethod
    def stat_commit_tx_end_success(self):
        """Add successfully finished TX"""

    @abstractmethod
    def stat_commit_tx_end_failed(self, err: Optional[Exception]):
        """Add failed TX"""

    @abstractmethod
    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: Decimal):
        """Operator Balance in Sol\'s"""

    @abstractmethod
    def stat_commit_operator_neon_balance(self, sol_acc: str, neon_acc: str, neon_balance: Decimal):
        """Operator Balance in Neon\'s"""

    @abstractmethod
    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal):
        """GAS Parameters"""

    @abstractmethod
    def stat_commit_tx_sol_spent(self, neon_tx_hash: str, sol_spent: int):
        """How many SOLs being spend in Neon transaction per iteration"""

    @abstractmethod
    def stat_commit_tx_steps_bpf(self, neon_tx_hash: str, steps: int, bpf: int):
        """How many Steps/BPF cycles was used in each iteration"""

    @abstractmethod
    def stat_commit_tx_count(self, canceled: bool = False):
        """Count of Neon transactions were completed (independent on status)"""

    @abstractmethod
    def stat_commit_count_sol_tx_per_neon_tx(self, type: str, sol_tx_count: int):
        """Count of transactions by type(single\iter\iter w holder)"""

    @abstractmethod
    def stat_commit_postgres_availability(self, status: bool):
        """Postgres availability"""

    @abstractmethod
    def stat_commit_solana_rpc_health(self, status: bool):
        """Solana Node status"""
