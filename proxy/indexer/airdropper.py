from web3 import eth
from proxy.indexer.indexer_base import IndexerBase, logger
from proxy.indexer.price_provider import PriceProvider, mainnet_solana, mainnet_price_accounts
from typing import List, Dict
import os
import requests
import base58
import json
import logging
from datetime import date, datetime

try:
    from utils import check_error
    from sql_dict import SQLDict
except ImportError:
    from .utils import check_error
    from .sql_dict import SQLDict

ACCOUNT_CREATION_PRICE_SOL = 0.00472692
AIRDROP_AMOUNT_SOL = ACCOUNT_CREATION_PRICE_SOL / 2
NEON_PRICE_USD = 0.25


class Airdropper(IndexerBase):
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 faucet_url = '',
                 wrapper_whitelist = 'ANY',
                 log_level = 'INFO',
                 price_upd_interval=60,
                 neon_decimals = 9,
                 start_slot = 0):
        IndexerBase.__init__(self, solana_url, evm_loader_id, log_level, start_slot)
        self.latest_processed_slot = 0

        # collection of eth-address-to-create-accout-trx mappings
        # for every addresses that was already funded with airdrop
        self.airdrop_ready = SQLDict(tablename="airdrop_ready")
        self.airdrop_scheduled = SQLDict(tablename="airdrop_scheduled")
        self.wrapper_whitelist = wrapper_whitelist
        self.faucet_url = faucet_url

        # Price provider need pyth.network be deployed onto solana
        # so using mainnet solana for simplicity
        self.price_provider = PriceProvider(mainnet_solana,
                                            price_upd_interval, # seconds
                                            mainnet_price_accounts)
        self.neon_decimals = neon_decimals
        self.session = requests.Session()

        self.sol_price_usd = None
        self.airdrop_amount_usd = None
        self.airdrop_amount_neon = None


    # helper function checking if given contract address is in whitelist
    def is_allowed_wrapper_contract(self, contract_addr):
        if self.wrapper_whitelist == 'ANY':
            return True
        return contract_addr in self.wrapper_whitelist


    # helper function checking if given 'create account' corresponds to 'create erc20 token account' instruction
    def check_create_instr(self, account_keys, create_acc, create_token_acc):
        # Must use the same Ethereum account
        if account_keys[create_acc['accounts'][1]] != account_keys[create_token_acc['accounts'][2]]:
            return False
        # Must use the same token program
        if account_keys[create_acc['accounts'][5]] != account_keys[create_token_acc['accounts'][6]]:
            return False
        # Token program must be system token program
        if account_keys[create_acc['accounts'][5]] != 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA':
            return False
        # CreateERC20TokenAccount instruction must use ERC20-wrapper from whitelist
        if not self.is_allowed_wrapper_contract(account_keys[create_token_acc['accounts'][3]]):
            return False
        return True


    # helper function checking if given 'create erc20 token account' corresponds to 'token transfer' instruction
    def check_transfer(self, account_keys, create_token_acc, token_transfer) -> bool:
        return account_keys[create_token_acc['accounts'][1]] == account_keys[token_transfer['accounts'][1]]


    def airdrop_to(self, eth_address, airdrop_galans):
        logger.info(f"Airdrop {airdrop_galans} Galans to address: {eth_address}")
        json_data = { 'wallet': eth_address, 'amount': airdrop_galans }
        resp = self.session.post(self.faucet_url + '/request_neon_in_galans', json = json_data)
        if not resp.ok:
            logger.warning(f'Failed to airdrop: {resp.status_code}')
            return False

        return True


    def process_trx_airdropper_mode(self, trx):
        if check_error(trx):
            return

        # helper function finding all instructions that satisfies predicate
        def find_instructions(trx, predicate):
            return [instr for instr in trx['transaction']['message']['instructions'] if predicate(instr)]

        account_keys = trx["transaction"]["message"]["accountKeys"]

        # Finding instructions specific for airdrop.
        # Airdrop triggers on sequence:
        # neon.CreateAccount -> neon.CreateERC20TokenAccount -> spl.Transfer (maybe shuffled)
        # First: select all instructions that can form such chains
        predicate = lambda instr: account_keys[instr['programIdIndex']] == self.evm_loader_id \
                                  and base58.b58decode(instr['data'])[0] == 0x02
        create_acc_list = find_instructions(trx, predicate)

        predicate = lambda  instr: account_keys[instr['programIdIndex']] == self.evm_loader_id \
                                   and base58.b58decode(instr['data'])[0] == 0x0f
        create_token_acc_list = find_instructions(trx, predicate)

        predicate = lambda instr: account_keys[instr['programIdIndex']] == 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' \
                                  and base58.b58decode(instr['data'])[0] == 0x03
        token_transfer_list = find_instructions(trx, predicate)

        # Second: Find exact chains of instructions in sets created previously
        for create_acc in create_acc_list:
            for create_token_acc in create_token_acc_list:
                if not self.check_create_instr(account_keys, create_acc, create_token_acc):
                    continue
                for token_transfer in token_transfer_list:
                    if not self.check_transfer(account_keys, create_token_acc, token_transfer):
                        continue
                    self.schedule_airdrop(create_acc)


    def get_airdrop_amount_galans(self):
        new_sol_price_usd = self.price_provider.get_price('SOL/USD')
        if new_sol_price_usd is None:
            logger.warning("Failed to get SOL/USD price")
            return None

        if new_sol_price_usd != self.sol_price_usd:
            self.sol_price_usd = new_sol_price_usd
            logger.info(f"NEON price: ${NEON_PRICE_USD}")
            logger.info(f'SOL/USD = ${self.sol_price_usd}')
            self.airdrop_amount_usd = AIRDROP_AMOUNT_SOL * self.sol_price_usd
            self.airdrop_amount_neon = self.airdrop_amount_usd / NEON_PRICE_USD
            logger.info(f"Airdrop amount: ${self.airdrop_amount_usd} ({self.airdrop_amount_neon} NEONs)\n")

        return int(self.airdrop_amount_neon * pow(10, self.neon_decimals))


    def schedule_airdrop(self, create_acc):
        eth_address = "0x" + bytearray(base58.b58decode(create_acc['data'])[20:][:20]).hex()
        if eth_address in self.airdrop_ready or eth_address in self.airdrop_scheduled:
            # Target account already supplied with airdrop or airdrop already scheduled
            return
        logger.info(f'Scheduling airdrop for {eth_address}')
        self.airdrop_scheduled[eth_address] = { 'scheduled': datetime.now().timestamp() }


    def process_scheduled_trxs(self):
        airdrop_galans = self.get_airdrop_amount_galans()
        if airdrop_galans is None:
            logger.warning('Failed to estimate airdrop amount. Defer scheduled airdrops.')
            return

        success_addresses = set()
        for eth_address, sched_info in self.airdrop_scheduled.items():
            if not self.airdrop_to(eth_address, airdrop_galans):
                continue
            success_addresses.add(eth_address)
            self.airdrop_ready[eth_address] = { 'amount': airdrop_galans, 
                                                'scheduled': sched_info['scheduled'],
                                                'finished': datetime.now().timestamp() }

        for eth_address in success_addresses:
            del self.airdrop_scheduled[eth_address]


    def process_functions(self):
        """
        Overrides IndexerBase.process_functions
        """
        IndexerBase.process_functions(self)
        logger.debug("Process receipts")
        self.process_receipts()
        self.process_scheduled_trxs()


    def process_receipts(self):
        max_slot = 0
        for slot, _, trx in self.transaction_receipts.get_trxs(self.latest_processed_slot, reverse=True):
            max_slot = max(max_slot, slot)
            if trx['transaction']['message']['instructions'] is not None:
                self.process_trx_airdropper_mode(trx)
        self.latest_processed_slot = max(self.latest_processed_slot, max_slot)


def run_airdropper(solana_url,
                   evm_loader_id,
                   faucet_url = '',
                   wrapper_whitelist = 'ANY',
                   log_level = 'INFO',
                   price_update_interval = 60,
                   neon_decimals = 9,
                   start_slot = 0):
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id},
        log_level: {log_level},
        faucet_url: {faucet_url},
        wrapper_whitelist: {wrapper_whitelist},
        price update interval: {price_update_interval},
        NEON decimals: {neon_decimals},
        Start slot: {start_slot}""")

    airdropper = Airdropper(solana_url,
                            evm_loader_id,
                            faucet_url,
                            wrapper_whitelist,
                            log_level,
                            price_update_interval,
                            neon_decimals,
                            start_slot)
    airdropper.run()
