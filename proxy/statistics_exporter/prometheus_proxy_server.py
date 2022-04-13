import time
import traceback
from decimal import Decimal
from logged_groups import logged_group
from multiprocessing import Process

from prometheus_client import start_http_server
from ..common_neon.address import EthereumAddress
from ..common_neon.solana_interactor import SolanaInteractor
from ..environment import PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, SOLANA_URL, get_solana_accounts
from ..common_neon.gas_price_calculator import GasPriceCalculator

from .prometheus_proxy_exporter import PrometheusExporter


@logged_group("neon.ProxyStatExporter")
class PrometheusProxyServer:
    def __init__(self):
        self._stat_exporter = PrometheusExporter()
        self._solana = SolanaInteractor(SOLANA_URL)
        if PP_SOLANA_URL == SOLANA_URL:
            self._gas_price_calculator = GasPriceCalculator(self._solana, PYTH_MAPPING_ACCOUNT)
        else:
            self._gas_price_calculator = GasPriceCalculator(SolanaInteractor(PP_SOLANA_URL), PYTH_MAPPING_ACCOUNT)

        self._gas_price_calculator.update_mapping()
        self._gas_price_calculator.try_update_gas_price()

        self._operator_accounts = get_solana_accounts()
        self._sol_accounts = []
        self._neon_accounts = []
        for account in self._operator_accounts:
            self._sol_accounts.append(str(account.public_key()))
            self._neon_accounts.append(EthereumAddress.from_private_key(account.secret_key()))

        self.start_http_server()
        self.run_commit_process()

    @staticmethod
    def start_http_server():
        from .prometheus_proxy_metrics import registry
        start_http_server(8888, registry=registry)

    def run_commit_process(self):
        p = Process(target=self.commit_loop)
        p.start()

    def commit_loop(self):
        while True:
            time.sleep(5)
            try:
                self._stat_operator_balance()
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning('Exception on transactions processing. ' +
                             f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def _stat_operator_balance(self):
        sol_balances = self._solana.get_sol_balance_list(self._sol_accounts)
        operator_sol_balance = dict(zip(self._sol_accounts, sol_balances))
        for account, balance in operator_sol_balance.items():
            self._stat_exporter.stat_commit_operator_sol_balance(str(account), Decimal(balance) / 1_000_000_000)

        neon_layouts = self._solana.get_neon_account_info_list(self._neon_accounts)
        for sol_account, neon_account, neon_layout in zip(self._operator_accounts, self._neon_accounts, neon_layouts):
            if neon_layout:
                neon_balance = Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000
                self._stat_exporter.stat_commit_operator_neon_balance(str(sol_account), str(neon_account), neon_balance)

    def _stat_gas_price(self):
        self._stat_exporter.stat_commit_gas_parameters(
            self._gas_price_calculator.get_suggested_gas_price(),
            self._gas_price_calculator.get_sol_price_usd(),
            self._gas_price_calculator.get_neon_price_usd(),
            self._gas_price_calculator.get_operator_fee(),
        )
