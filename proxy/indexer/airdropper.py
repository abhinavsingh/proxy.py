from proxy.indexer.indexer_base import IndexerBase, logger
from proxy.indexer.price_provider import PriceProvider, mainnet_solana, mainnet_price_accounts
import os
import requests
import base58
import json
import logging

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
                 wrapper_whitelist = [],
                 log_level = 'INFO',
                 price_upd_interval=60,
                 neon_decimals = 9):
        IndexerBase.__init__(self, solana_url, evm_loader_id, log_level)

        # collection of eth-address-to-create-accout-trx mappings
        # for every addresses that was already funded with airdrop
        self.airdrop_ready = SQLDict(tablename="airdrop_ready")
        self.wrapper_whitelist = wrapper_whitelist
        self.faucet_url = faucet_url

        # Price provider need pyth.network be deployed onto solana
        # so using mainnet solana for simplicity
        self.price_provider = PriceProvider(mainnet_solana,
                                            price_upd_interval,
                                            mainnet_price_accounts)
        self.neon_decimals = neon_decimals


    # helper function checking if given contract address is in whitelist
    def _is_allowed_wrapper_contract(self, contract_addr):
        return contract_addr in self.wrapper_whitelist


    # helper function checking if given 'create account' corresponds to 'create erc20 token account' instruction
    def _check_create_instr(self, account_keys, create_acc, create_token_acc):
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
        if not self._is_allowed_wrapper_contract(account_keys[create_token_acc['accounts'][3]]):
            return False
        return True


    # helper function checking if given 'create erc20 token account' corresponds to 'token transfer' instruction
    def _check_transfer(self, account_keys, create_token_acc, token_transfer) -> bool:
        return account_keys[create_token_acc['accounts'][1]] == account_keys[token_transfer['accounts'][1]]


    def _airdrop_to(self, create_acc):
        eth_address = "0x" + bytearray(base58.b58decode(create_acc['data'])[20:][:20]).hex()
        if eth_address in self.airdrop_ready:  # transaction already processed
            return

        sol_price_usd = self.price_provider.get_price('SOL/USD')
        if sol_price_usd is None:
            logger.warning("Failed to get SOL/USD price")
            return

        logger.info(f'SOL/USD = ${sol_price_usd}')
        airdrop_amount_usd = AIRDROP_AMOUNT_SOL * sol_price_usd
        logger.info(f"Airdrop amount: ${airdrop_amount_usd}")
        logger.info(f"NEON price: ${NEON_PRICE_USD}")
        airdrop_amount_neon = airdrop_amount_usd / NEON_PRICE_USD
        logger.info(f"Airdrop {airdrop_amount_neon} NEONs to address: {eth_address}")
        airdrop_galans = int(airdrop_amount_neon * pow(10, self.neon_decimals))

        json_data = { 'wallet': eth_address, 'amount': airdrop_galans }
        resp = requests.post(self.faucet_url + '/request_neon_in_galans', json = json_data)
        if not resp.ok:
            logger.warning(f'Failed to airdrop: {resp.status_code}')
            return
        
        self.airdrop_ready[eth_address] = create_acc


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
                if not self._check_create_instr(account_keys, create_acc, create_token_acc):
                    continue
                for token_transfer in token_transfer_list:
                    if not self._check_transfer(account_keys, create_token_acc, token_transfer):
                        continue
                    self._airdrop_to(create_acc)


    def process_functions(self):
        IndexerBase.process_functions(self)
        logger.debug("Process receipts")
        self.process_receipts()


    def process_receipts(self):
        counter = 0
        for signature in self.transaction_order:
            counter += 1
            if signature in self.transaction_receipts:
                trx = self.transaction_receipts[signature]
                if trx is None:
                    logger.error("trx is None")
                    del self.transaction_receipts[signature]
                    continue
                if 'slot' not in trx:
                    logger.debug("\n{}".format(json.dumps(trx, indent=4, sort_keys=True)))
                    exit()
                if trx['transaction']['message']['instructions'] is not None:
                    self.process_trx_airdropper_mode(trx)


def run_airdropper(solana_url,
                   evm_loader_id,
                   faucet_url = '',
                   wrapper_whitelist = [],
                   log_level = 'INFO',
                   price_update_interval = 60,
                   neon_decimals = 9):
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id},
        log_level: {log_level},
        faucet_url: {faucet_url},
        wrapper_whitelist: {wrapper_whitelist},
        price update interval: {price_update_interval},
        NEON decimals: {neon_decimals}""")

    airdropper = Airdropper(solana_url,
                            evm_loader_id,
                            faucet_url,
                            wrapper_whitelist,
                            log_level,
                            price_update_interval,
                            neon_decimals)
    airdropper.run()
