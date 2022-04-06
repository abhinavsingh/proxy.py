from decimal import Decimal
from multiprocessing import Process
import time
import traceback
from typing import Dict, Tuple
from prometheus_client import start_http_server
from proxy.common_neon.address import EthereumAddress
from proxy.common_neon.solana_interactor import SolanaInteractor

from proxy.environment import PP_SOLANA_URL, PYTH_MAPPING_ACCOUNT, SOLANA_URL, get_solana_accounts
from proxy.plugin.gas_price_calculator import GasPriceCalculator
from .prometheus_proxy_exporter import PrometheusExporter


class PrometheusProxyServer:
    def __init__(self):
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
        self.stat_exporter = PrometheusExporter()
        self._solana = SolanaInteractor(SOLANA_URL)
        if PP_SOLANA_URL == SOLANA_URL:
            self.gas_price_calculator = GasPriceCalculator(self._solana, PYTH_MAPPING_ACCOUNT)
        else:
            self.gas_price_calculator = GasPriceCalculator(SolanaInteractor(PP_SOLANA_URL), PYTH_MAPPING_ACCOUNT)
        self.gas_price_calculator.update_mapping()
        self.gas_price_calculator.try_update_gas_price()

        while True:
            time.sleep(5)
            try:
                self._stat_operator_balance()
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning('Exception on transactions processing. ' +
                             f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def _stat_operator_balance(self):
        operator_accounts = get_solana_accounts()
        sol_accounts = [str(sol_account.public_key()) for sol_account in operator_accounts]
        sol_balances = self._solana.get_sol_balance_list(sol_accounts)
        operator_sol_balance = dict(zip(sol_accounts, sol_balances))
        for account, balance in operator_sol_balance.items():
            self.stat_exporter.stat_commit_operator_sol_balance(str(account), Decimal(balance) / 1_000_000_000)

        neon_accounts = [str(EthereumAddress.from_private_key(neon_account.secret_key())) for neon_account in operator_accounts]
        neon_layouts = self._solana.get_account_info_layout_list(neon_accounts)
        for sol_account, neon_account, neon_layout in zip(operator_accounts, neon_accounts, neon_layouts):
            if neon_layout:
                neon_balance = Decimal(neon_layout.balance) / 1_000_000_000 / 1_000_000_000
                self.stat_exporter.stat_commit_operator_neon_balance(str(sol_account), str(neon_account), neon_balance)

    def _stat_gas_price(self):
        self.stat_exporter.stat_commit_gas_parameters(
            self.gas_price_calculator.get_suggested_gas_price(),
            self.gas_price_calculator.get_sol_price_usd(),
            self.gas_price_calculator.get_neon_price_usd(),
            self.gas_price_calculator.get_operator_fee(),
        )
