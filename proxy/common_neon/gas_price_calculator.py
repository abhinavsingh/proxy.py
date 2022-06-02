from datetime import datetime
from decimal import Decimal
import time
import math
from logged_groups import logged_group
import multiprocessing as mp
import ctypes
from ..indexer.pythnetwork import PythNetworkClient
from ..common_neon.solana_interactor import SolanaInteractor
from .environment_data import MINIMAL_GAS_PRICE, OPERATOR_FEE, GAS_PRICE_SUGGESTED_PCT, NEON_PRICE_USD, \
                              SOL_PRICE_UPDATE_INTERVAL, GET_SOL_PRICE_MAX_RETRIES, GET_SOL_PRICE_RETRY_INTERVAL


@logged_group("neon.gas_price_calculator")
class GasPriceCalculator:
    _last_time = mp.Value(ctypes.c_ulonglong, 0)
    _min_gas_price = mp.Value(ctypes.c_ulonglong, 0)
    _suggested_gas_price = mp.Value(ctypes.c_ulonglong, 0)

    def __init__(self, solana: SolanaInteractor, pyth_mapping_acc) -> None:
        self.solana = solana
        self.mapping_account = pyth_mapping_acc
        self.pyth_network_client = PythNetworkClient(self.solana)
        self.recent_sol_price_update_time = None
        self.min_gas_price = None
        self.sol_price_usd = None

    def reset(self):
        self._last_time.value = 0

    @staticmethod
    def env_min_gas_price() -> int:
        if MINIMAL_GAS_PRICE is not None:
            return MINIMAL_GAS_PRICE

    @staticmethod
    def get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def update_mapping(self):
        if self.mapping_account is not None:
            self.pyth_network_client.update_mapping(self.mapping_account)

    def get_min_gas_price(self) -> int:
        self.try_update_gas_price()
        gas_price = self._min_gas_price.value
        if not gas_price:
            raise RuntimeError('Failed to estimate gas price. Try again later')
        return gas_price

    def get_suggested_gas_price(self) -> int:
        self.try_update_gas_price()
        gas_price = self._suggested_gas_price.value
        if not gas_price:
            raise RuntimeError('Failed to estimate gas price. Try again later')
        return gas_price

    def try_update_gas_price(self):
        def is_time_come(now, prev_time) -> bool:
            time_diff = now - prev_time
            return time_diff > SOL_PRICE_UPDATE_INTERVAL

        now = self.get_current_time()
        if not is_time_come(now, self._last_time.value):
            return

        with self._last_time.get_lock():
            if not is_time_come(now, self._last_time.value):
                return
            self._last_time.value = now

        gas_price = self.env_min_gas_price()
        if gas_price:
            self._suggested_gas_price.value = gas_price
            self._min_gas_price.value = gas_price
            return

        gas_price = self._start_update_gas_price()
        if not gas_price:
            return

        self._suggested_gas_price.value = math.ceil(gas_price * (1 + GAS_PRICE_SUGGESTED_PCT + OPERATOR_FEE))
        self._min_gas_price.value = math.ceil(gas_price * (1 + OPERATOR_FEE))

    def _start_update_gas_price(self) -> int:
        for retry in range(GET_SOL_PRICE_MAX_RETRIES):
            try:
                price = self.pyth_network_client.get_price('Crypto.SOL/USD')
                if price['status'] != 1:  # tradable
                    raise RuntimeError('Price status is not tradable')
                self.sol_price_usd = Decimal(price['price'])

                return (self.sol_price_usd / NEON_PRICE_USD) * pow(Decimal(10), 9)
            except Exception as err:
                self.error(f'Failed to retrieve SOL price: {err}')
                self.info(f'Will retry getting price after {GET_SOL_PRICE_RETRY_INTERVAL} seconds')
                time.sleep(GET_SOL_PRICE_RETRY_INTERVAL)
        with self._last_time.get_lock():
            self._last_time.value = 0
        self.error('Failed to estimate gas price. Try again later')
        return 0

    def get_sol_price_usd(self) -> Decimal:
        if self.sol_price_usd:
            return self.sol_price_usd
        return Decimal(0)

    def get_neon_price_usd(self) -> Decimal:
        return NEON_PRICE_USD

    def get_operator_fee(self) -> Decimal:
        return OPERATOR_FEE
