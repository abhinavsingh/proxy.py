from abc import ABC, abstractmethod
from decimal import Decimal


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
    def stat_commit_tx_end_failed(self, err: Exception):
        """Add failed TX"""

    @abstractmethod
    def stat_commit_tx_balance_change(self, sol_acc: str, sol_diff: Decimal, neon_acc: str, neon_diff: Decimal):
        """Operator Sol and Neon balance changes on TX"""

    @abstractmethod
    def stat_commit_operator_sol_balance(self, operator: str, sol_balance: Decimal):
        """Operator Balance in Sol\'s"""

    @abstractmethod
    def stat_commit_operator_neon_balance(self, sol_acc: str, neon_acc: str, neon_balance: Decimal):
        """Operator Balance in Neon\'s"""

    @abstractmethod
    def stat_commit_create_resource_account(self, account: str, rent: Decimal):
        """Created resource account and its rent"""

    @abstractmethod
    def stat_commit_gas_parameters(self, gas_price: int, sol_price_usd: Decimal, neon_price_usd: Decimal, operator_fee: Decimal):
        """GAS Parameters"""
