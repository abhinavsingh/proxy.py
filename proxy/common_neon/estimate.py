import json
from logged_groups import logged_group

from proxy.common_neon.emulator_interactor import call_emulated
from ..common_neon.utils import get_holder_msg
from ..environment import CONTRACT_EXTRA_SPACE, EXTRA_GAS, CHAIN_ID, HOLDER_MSG_SIZE
from .eth_proto import Trx as EthTrx
from .solana_interactor import SolanaInteractor
from .layouts import ACCOUNT_INFO_LAYOUT



@logged_group("neon.Proxy")
class GasEstimate:
    def __init__(self, request: dict, solana: SolanaInteractor):
        self.sender = request.get('from', "0x0000000000000000000000000000000000000000")[2:]
        self.contract = request.get('to', '0x')[2:]
        self.value = request.get('value', '0x00')
        self.data = request.get('data', '0x')[2:]

        self.solana = solana

    @logged_group("neon.Proxy")
    def execution_cost(self, *, logger) -> int:
        result = call_emulated(self.contract or "deploy", self.sender, self.data, self.value)
        self.debug(f'emulator returns: {json.dumps(result, indent=3)}')

        # Gas used in emulatation
        cost = result['used_gas']

        # Some accounts may not exist at the emulation time 
        # Calculate gas for them separately
        accounts_size = [
            a["code_size"] + CONTRACT_EXTRA_SPACE
            for a in result["accounts"]
            if (not a["code_size_current"]) and a["code_size"]
        ]

        if not accounts_size:
            return cost

        accounts_size.append(ACCOUNT_INFO_LAYOUT.sizeof())
        balances = self.solana.get_multiple_rent_exempt_balances_for_size(accounts_size)

        for balance in balances[:-1]:
            cost += balances[-1]
            cost += balance

        return cost

    @logged_group("neon.Proxy")
    def trx_size_cost(self, *, logger) -> int:
        u256_max = int.from_bytes(bytes([0xFF] * 32), "big")

        trx = EthTrx(
            nonce = u256_max,
            gasPrice = u256_max,
            gasLimit = u256_max,
            toAddress = bytes.fromhex(self.contract),
            value = int(self.value, 16),
            callData = bytes.fromhex(self.data),
            v = CHAIN_ID * 2 + 35,
            r = 0x1820182018201820182018201820182018201820182018201820182018201820,
            s = 0x1820182018201820182018201820182018201820182018201820182018201820
        )
        msg = get_holder_msg(trx)
        return ((len(msg) // HOLDER_MSG_SIZE) + 1) * 5000

    @logged_group("neon.Proxy")
    def iterative_overhead_cost(self, *, logger) -> int:
        last_iteration_cost = 5000
        cancel_cost = 5000

        return last_iteration_cost + cancel_cost

    @logged_group("neon.Proxy")
    def estimate(self, *, logger):
        execution_cost = self.execution_cost()
        trx_size_cost = self.trx_size_cost()
        overhead = self.iterative_overhead_cost()

        gas = execution_cost + trx_size_cost + overhead + EXTRA_GAS

        # TODO: MM restriction. Uncomment ?
        # if gas < 21000:
        #     gas = 21000

        logger.debug(f'execution_cost: {execution_cost}')
        logger.debug(f'trx_size_cost: {trx_size_cost}')
        logger.debug(f'iterative_overhead: {overhead}')
        logger.debug(f'extra_gas: {EXTRA_GAS}')
        logger.debug(f'estimated gas: {gas}')

        return hex(gas)
