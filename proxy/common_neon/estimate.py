import os
import math
from web3.auto import w3

from solana.publickey import PublicKey
from logged_groups import logged_group
from typing import Tuple

from ..common_neon.utils import get_holder_msg
from ..common_neon.transaction_sender import NeonTxSender, NeonCreateContractTxStage, NeonCreateAccountTxStage
from ..environment import   EXTRA_GAS, EVM_STEPS,  EVM_BYTE_COST, HOLDER_MSG_SIZE, LAMPORTS_PER_SIGNATURE, \
    ACCOUNT_MAX_SIZE, SPL_TOKEN_ACCOUNT_SIZE, PAYMENT_TO_TREASURE, ACCOUNT_STORAGE_OVERHEAD
from eth_keys import keys as eth_keys
from .eth_proto import Trx as EthTrx


def evm_step_cost(signature_cnt):
    operator_expences = PAYMENT_TO_TREASURE + LAMPORTS_PER_SIGNATURE * signature_cnt
    return math.ceil(operator_expences / EVM_STEPS)


@logged_group("neon.Proxy")
class GasEstimate:
    def __init__(self, request, db, solana, evm_step_count):
        self.sender: bytes = bytes.fromhex(request.get('from', "0x%040x" % 0x0)[2:])
        self.step_count = evm_step_count

        contract = request.get('to', None)
        contract = bytes.fromhex(contract[2:]) if contract else ""

        value = request.get('value', None)
        value = int(value, 16) if value else 0

        data = request.get('data', None)
        data = data[2:] if data else ""

        unsigned_trx = {
            'to': contract,
            'value': value,
            'gas': 999999999,
            'gasPrice': 1_000_000_000,
            'nonce': 0xffff,
            'data': data,
            'chainId': int('ffffffff', 16)
        }
        signed_trx = w3.eth.account.sign_transaction(unsigned_trx, eth_keys.PrivateKey(os.urandom(32)))
        trx = EthTrx.fromString(signed_trx.rawTransaction)

        self.tx_sender = NeonTxSender(db, solana, trx, steps=evm_step_count)

    def iteration_info(self) -> Tuple[int, int]:
        if self.tx_sender.steps_emulated > 0:
            full_step_iterations = int(self.tx_sender.steps_emulated / self.step_count)
            final_steps = self.tx_sender.steps_emulated % self.step_count
            if final_steps > 0 and final_steps < EVM_STEPS:
                final_steps = EVM_STEPS
        else:
            full_step_iterations = 0
            final_steps = EVM_STEPS
        return final_steps, full_step_iterations

    def simple_neon_tx_strategy(self):
        gas = evm_step_cost(2) * (self.tx_sender.steps_emulated if self.tx_sender.steps_emulated > EVM_STEPS else EVM_STEPS)
        self.debug(f'estimate simple_neon_tx_strategy: {gas}')
        return gas

    def iterative_neon_tx_strategy(self):
        begin_iteration = 1
        final_steps, full_step_iterations = self.iteration_info()
        steps = begin_iteration * EVM_STEPS + full_step_iterations * self.step_count + final_steps
        gas = steps * evm_step_cost(1)
        self.debug(f'estimate iterative_neon_tx_strategy: {gas}')
        return gas

    def holder_neon_tx_strategy(self):
        begin_iteration = 1
        msg = get_holder_msg(self.tx_sender.eth_tx)
        holder_iterations = math.ceil(len(msg) / HOLDER_MSG_SIZE)
        final_steps, full_step_iterations = self.iteration_info()
        steps = (begin_iteration + holder_iterations) * EVM_STEPS + full_step_iterations * self.step_count + final_steps
        gas = steps * evm_step_cost(1)
        self.debug(f'estimate holder_neon_tx_strategy: {gas}')
        return gas

    def allocated_space(self):
        space = 0
        for s in self.tx_sender._create_account_list:
            if s.NAME == NeonCreateContractTxStage.NAME:
                space += s.size + ACCOUNT_MAX_SIZE + SPL_TOKEN_ACCOUNT_SIZE + ACCOUNT_STORAGE_OVERHEAD*3
            elif s.NAME == NeonCreateAccountTxStage.NAME:
                space += ACCOUNT_MAX_SIZE + SPL_TOKEN_ACCOUNT_SIZE + ACCOUNT_STORAGE_OVERHEAD * 2

        space += self.tx_sender.unpaid_space
        self.debug(f'allocated space: {space}')
        return space

    def estimate(self):
        self.tx_sender.operator_key = PublicKey(os.urandom(32))
        self.tx_sender._call_emulated(self.sender)
        self.tx_sender._parse_accounts_list()

        gas_for_trx = max(self.simple_neon_tx_strategy(),  self.iterative_neon_tx_strategy(), self.holder_neon_tx_strategy())
        gas_for_space = self.allocated_space() * EVM_BYTE_COST
        gas = gas_for_trx + gas_for_space + EXTRA_GAS

        # TODO: MM restriction. Uncomment ?
        # if gas < 21000:
        #     gas = 21000

        self.debug(f'extra_gas: {EXTRA_GAS}')
        self.debug(f'gas_for_space: {gas_for_space}')
        self.debug(f'gas_for_trx: {gas_for_trx}')
        self.debug(f'estimated gas: {gas}')
        return hex(gas)
