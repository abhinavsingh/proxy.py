from calendar import c
from solana.publickey import PublicKey
from proxy.indexer.indexer_base import IndexerBase
from proxy.indexer.pythnetwork import PythNetworkClient
from proxy.indexer.utils import BaseDB
from solana.rpc.api import Client as SolanaClient
import requests
import base58
from datetime import datetime
from decimal import Decimal
import os
from logged_groups import logged_group
from ..environment import NEON_PRICE_USD

try:
    from utils import check_error
    from sql_dict import SQLDict
except ImportError:
    from .utils import check_error
    from .sql_dict import SQLDict

ACCOUNT_CREATION_PRICE_SOL = Decimal('0.00472692')
AIRDROP_AMOUNT_SOL = ACCOUNT_CREATION_PRICE_SOL / 2


class FailedAttempts(BaseDB):
    def __init__(self) -> None:
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'failed_airdrop_attempts'
        return f'''
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                attempt_time    BIGINT,
                eth_address     TEXT,
                reason          TEXT
            );
            CREATE INDEX IF NOT EXISTS failed_attempt_time_idx ON {self._table_name} (attempt_time);
            '''

    def airdrop_failed(self, eth_address, reason):
        with self._conn.cursor() as cur:
            cur.execute(f'''
            INSERT INTO {self._table_name} (attempt_time, eth_address, reason)
            VALUES ({datetime.now().timestamp()}, '{eth_address}', '{reason}')
            ''')


class AirdropReadySet:
    def __init__(self) -> None:
        BaseDB.__init__(self)

    def _create_table_sql(self) -> str:
        self._table_name = 'airdrop_ready'
        return f'''
            CREATE TABLE IF NOT EXISTS {self._table_name} (
                eth_address     TEXT UNIQUE,
                scheduled_ts    BIGINT,
                finished_ts     BIGINT,
                duration        INTEGER,
                amount_galans   INTEGER
            )
            '''

    def register_airdrop(self, eth_address: str, airdrop_info: dict):
        finished = int(datetime.now().timestamp())
        duration = finished - airdrop_info['scheduled']
        with self._conn.cursor() as cur:
            cur.execute(f'''
            INSERT INTO {self._table_name} (eth_address, scheduled_ts, finished_ts, duration, amount_galans)
            VALUES ('{eth_address}', {airdrop_info['scheduled']}, {finished}, {duration}, {airdrop_info['amount']})
            ''')

    def is_airdrop_ready(self, eth_address):
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT 1 FROM {self._table_name} WHERE eth_address = '{eth_address}'")
            return cur.fetchone() is not None

FINALIZED = os.environ.get('FINALIZED', 'finalized')


@logged_group("neon.Airdropper")
class Airdropper(IndexerBase):
    def __init__(self,
                 solana_url,
                 evm_loader_id,
                 pyth_mapping_account: PublicKey,
                 faucet_url = '',
                 wrapper_whitelist = 'ANY',
                 neon_decimals = 9,
                 pp_solana_url = None,
                 max_conf = 0.1): # maximum confidence interval deviation related to price
        self._constants = SQLDict(tablename="constants")

        last_known_slot = self._constants.get('latest_processed_slot', None)
        IndexerBase.__init__(self, solana_url, evm_loader_id, last_known_slot)
        self.latest_processed_slot = self.last_slot

        # collection of eth-address-to-create-accout-trx mappings
        # for every addresses that was already funded with airdrop
        self.airdrop_ready = AirdropReadySet()
        self.failed_attempts = FailedAttempts()
        self.airdrop_scheduled = SQLDict(tablename="airdrop_scheduled")
        self.wrapper_whitelist = wrapper_whitelist
        self.faucet_url = faucet_url
        self.recent_price = None

        # Configure price provider
        if pp_solana_url is None:
            pp_solana_url = solana_url

        # It is possible to use different networks to obtain SOL price
        # but there will be different slot numbers so price should be updated every time
        self.always_reload_price = (pp_solana_url != solana_url)
        self.pyth_mapping_account = pyth_mapping_account
        self.pyth_client = PythNetworkClient(SolanaClient(pp_solana_url))
        self.neon_decimals = neon_decimals
        self.max_conf = Decimal(max_conf)
        self.session = requests.Session()

        self.sol_price_usd = None
        self.airdrop_amount_usd = None
        self.airdrop_amount_neon = None
        self.last_update_pyth_mapping = None
        self.max_update_pyth_mapping_int = 60 * 60 # update once an hour


    def get_current_time(self):
        return datetime.now().timestamp()


    def try_update_pyth_mapping(self):
        current_time = self.get_current_time()
        if self.last_update_pyth_mapping is None or self.last_update_pyth_mapping - current_time > self.max_update_pyth_mapping_int:
            try:
                self.pyth_client.update_mapping(self.pyth_mapping_account)
                self.last_update_pyth_mapping = current_time
            except Exception as err:
                self.warning(f'Failed to update pyth.network mapping account data: {err}')
                return False

        return True

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
        self.info(f"Airdrop {airdrop_galans} Galans to address: {eth_address}")
        json_data = { 'wallet': eth_address, 'amount': airdrop_galans }
        resp = self.session.post(self.faucet_url + '/request_neon_in_galans', json = json_data)
        if not resp.ok:
            self.warning(f'Failed to airdrop: {resp.status_code}')
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


    def get_sol_usd_price(self):
        should_reload = self.always_reload_price
        if not should_reload:
            if self.recent_price == None or self.recent_price['valid_slot'] < self.current_slot:
                should_reload = True

        if should_reload:
            try:
                self.recent_price = self.pyth_client.get_price('SOL/USD')
            except Exception as err:
                self.warning(f'Exception occured when reading price: {err}')
                return None

        return self.recent_price

    def get_airdrop_amount_galans(self):
        self.sol_price_usd = self.get_sol_usd_price()
        if self.sol_price_usd is None:
            self.warning("Failed to get SOL/USD price")
            return None

        self.info(f"NEON price: ${NEON_PRICE_USD}")
        self.info(f"Price valid slot: {self.sol_price_usd['valid_slot']}")
        self.info(f"Price confidence interval: ${self.sol_price_usd['conf']}")
        self.info(f"SOL/USD = ${self.sol_price_usd['price']}")
        if self.sol_price_usd['conf'] / self.sol_price_usd['price'] > self.max_conf:
            self.warning(f"Confidence interval too large. Airdrops will deferred.")
            return None

        self.airdrop_amount_usd = AIRDROP_AMOUNT_SOL * self.sol_price_usd['price']
        self.airdrop_amount_neon = self.airdrop_amount_usd / NEON_PRICE_USD
        self.info(f"Airdrop amount: ${self.airdrop_amount_usd} ({self.airdrop_amount_neon} NEONs)\n")
        return int(self.airdrop_amount_neon * pow(Decimal(10), self.neon_decimals))


    def schedule_airdrop(self, create_acc):
        eth_address = "0x" + bytearray(base58.b58decode(create_acc['data'])[20:][:20]).hex()
        if self.airdrop_ready.is_airdrop_ready(eth_address) or eth_address in self.airdrop_scheduled:
            # Target account already supplied with airdrop or airdrop already scheduled
            return
        self.info(f'Scheduling airdrop for {eth_address}')
        self.airdrop_scheduled[eth_address] = { 'scheduled': self.get_current_time() }


    def process_scheduled_trxs(self):
        # Pyth.network mapping account was never updated
        if not self.try_update_pyth_mapping() and self.last_update_pyth_mapping is None:
            self.failed_attempts.airdrop_failed('ALL', 'mapping is empty')
            return

        airdrop_galans = self.get_airdrop_amount_galans()
        if airdrop_galans is None:
            self.warning('Failed to estimate airdrop amount. Defer scheduled airdrops.')
            self.failed_attempts.airdrop_failed('ALL', 'fail to estimate amount')
            return

        success_addresses = set()
        for eth_address, sched_info in self.airdrop_scheduled.items():
            if not self.airdrop_to(eth_address, airdrop_galans):
                self.failed_attempts.airdrop_failed(str(eth_address), 'airdrop failed')
                continue
            success_addresses.add(eth_address)
            self.airdrop_ready.register_airdrop(eth_address,
                                                {
                                                    'amount': airdrop_galans,
                                                    'scheduled': sched_info['scheduled']
                                                })

        for eth_address in success_addresses:
            del self.airdrop_scheduled[eth_address]


    def process_functions(self):
        """
        Overrides IndexerBase.process_functions
        """
        IndexerBase.process_functions(self)
        self.debug("Process receipts")
        self.process_receipts()
        self.process_scheduled_trxs()


    def process_receipts(self):
        max_slot = 0
        for slot, _, trx in self.transaction_receipts.get_trxs(self.latest_processed_slot):
            max_slot = max(max_slot, slot)
            if trx['transaction']['message']['instructions'] is not None:
                self.process_trx_airdropper_mode(trx)
        self.latest_processed_slot = max(self.latest_processed_slot, max_slot)
        self._constants['latest_processed_slot'] = self.latest_processed_slot


@logged_group("neon.Airdropper")
def run_airdropper(solana_url,
                   evm_loader_id,
                   pyth_mapping_account: PublicKey,
                   faucet_url,
                   wrapper_whitelist = 'ANY',
                   neon_decimals = 9,
                   pp_solana_url = None,
                   max_conf = 0.1, *, logger):
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {evm_loader_id},
        pyth.network mapping account: {pyth_mapping_account},
        faucet_url: {faucet_url},
        wrapper_whitelist: {wrapper_whitelist},
        NEON decimals: {neon_decimals},
        Price provider solana: {pp_solana_url},
        Max confidence interval: {max_conf}""")

    try:
        airdropper = Airdropper(solana_url,
                                evm_loader_id,
                                pyth_mapping_account,
                                faucet_url,
                                wrapper_whitelist,
                                neon_decimals,
                                pp_solana_url,
                                max_conf)
        airdropper.run()
    except Exception as err:
        logger.error(f'Failed to start Airdropper: {err}')
