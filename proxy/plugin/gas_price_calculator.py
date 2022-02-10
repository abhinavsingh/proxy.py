from datetime import datetime
from decimal import Decimal
import time
from logged_groups import logged_group
from ..indexer.pythnetwork import PythNetworkClient
from ..environment import MINIMAL_GAS_PRICE, OPERATOR_FEE, NEON_PRICE_USD, \
    SOL_PRICE_UPDATE_INTERVAL, GET_SOL_PRICE_MAX_RETRIES, GET_SOL_PRICE_RETRY_INTERVAL


@logged_group("neon.gas_price_calculator")
class GasPriceCalculator:
    def __init__(self, solana_client, pyth_mapping_acc) -> None:
        self.solana_client = solana_client
        self.mapping_account = pyth_mapping_acc
        self.pyth_network_client = PythNetworkClient(self.solana_client)
        self.recent_sol_price_update_time = None
        self.min_gas_price = None

    def update_mapping(self):
        if self.mapping_account is not None:
            self.pyth_network_client.update_mapping(self.mapping_account)

    def get_min_gas_price(self):
        if MINIMAL_GAS_PRICE is not None:
            return MINIMAL_GAS_PRICE
        self.try_update_gas_price()
        return self.min_gas_price

    def try_update_gas_price(self):
        cur_time = self.get_current_time()
        if self.recent_sol_price_update_time is None:
            self.start_update_gas_price(cur_time)
            return

        time_left = cur_time - self.recent_sol_price_update_time
        if time_left > SOL_PRICE_UPDATE_INTERVAL:
            self.start_update_gas_price(cur_time)

    def get_current_time(self):
        return datetime.now().timestamp()

    def start_update_gas_price(self, cur_time):
        num_retries = GET_SOL_PRICE_MAX_RETRIES

        while True:
            try:
                price = self.pyth_network_client.get_price('Crypto.SOL/USD')
                if price['status'] != 1: # tradable
                    raise Exception('Price status is not tradable')

                self.recent_sol_price_update_time = cur_time
                self.min_gas_price = (price['price'] / NEON_PRICE_USD) * (1 + OPERATOR_FEE) * pow(Decimal(10), 9)
                return

            except Exception as err:
                self.error(f'Failed to retrieve SOL price: {err}')
                num_retries -= 1
                if num_retries == 0:
                    # This error should be forwarded to client
                    raise Exception('Failed to estimate gas price. Try again later')

                self.info(f'Will retry getting price after {GET_SOL_PRICE_RETRY_INTERVAL} seconds')
                time.sleep(GET_SOL_PRICE_RETRY_INTERVAL)