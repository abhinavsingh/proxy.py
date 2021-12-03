from proxy.indexer.indexer_base import IndexerBase, logger
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

class Airdropper(IndexerBase):
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 faucet_url = '',
                 wrapper_whitelist = [],
                 airdrop_amount = 10,
                 log_level = 'INFO'):
        IndexerBase.__init__(self, solana_url, evm_loader_id, log_level)

        # collection of eth-address-to-create-accout-trx mappings
        # for every addresses that was already funded with airdrop
        self.airdrop_ready = SQLDict(tablename="airdrop_ready")
        self.wrapper_whitelist = wrapper_whitelist
        self.airdrop_amount = airdrop_amount
        self.faucet_url = faucet_url


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

        logger.info(f"Airdrop to address: {eth_address}")

        json_data = { 'wallet': eth_address, 'amount': self.airdrop_amount }
        resp = requests.post(self.faucet_url + '/request_eth_token', json = json_data)
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
                   airdrop_amount = 10,
                   log_level = 'INFO'):
    logging.basicConfig(format='%(asctime)s - pid:%(process)d [%(levelname)-.1s] %(funcName)s:%(lineno)d - %(message)s')
    logger.setLevel(logging.DEBUG)
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id},
        log_level: {log_level},
        faucet_url: {faucet_url},
        wrapper_whitelist: {wrapper_whitelist},
        airdrop_amount: {airdrop_amount}""")

    airdropper = Airdropper(solana_url,
                            evm_loader_id,
                            faucet_url,
                            wrapper_whitelist,
                            airdrop_amount,
                            log_level)
    airdropper.run()


if __name__ == "__main__":
    solana_url = os.environ.get('SOLANA_URL', 'http://localhost:8899')
    evm_loader_id = os.environ.get('EVM_LOADER_ID', '53DfF883gyixYNXnM7s5xhdeyV8mVk9T4i2hGV9vG9io')
    faucet_url = os.environ.get('FAUCET_URL', 'http://localhost:3333')
    wrapper_whitelist = os.environ.get('INDEXER_ERC20_WRAPPER_WHITELIST', '').split(',')
    airdrop_amount = os.environ.get('AIRDROP_AMOUNT', 0)
    log_level = os.environ.get('LOG_LEVEL', 'INFO')

    run_airdropper(solana_url,
                   evm_loader_id,
                   faucet_url,
                   wrapper_whitelist,
                   airdrop_amount,
                   log_level)
