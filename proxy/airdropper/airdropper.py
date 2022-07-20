from solana.publickey import PublicKey
import requests
import base58
import traceback
from datetime import datetime
from decimal import Decimal
from logged_groups import logged_group

from ..common_neon.environment_data import EVM_LOADER_ID, NEON_PRICE_USD
from ..common_neon.solana_interactor import SolanaInteractor
from ..indexer.indexer_base import IndexerBase
from ..indexer.pythnetwork import PythNetworkClient
from ..indexer.base_db import BaseDB
from ..indexer.utils import check_error
from ..indexer.sql_dict import SQLDict

EVM_LOADER_CREATE_ACC           = 0x18
SPL_TOKEN_APPROVE               = 0x04
EVM_LOADER_CALL_FROM_RAW_TRX    = 0x05
SPL_TOKEN_INIT_ACC_2            = 0x10
SPL_TOKEN_TRANSFER              = 0x03

ACCOUNT_CREATION_PRICE_SOL = Decimal('0.00472692')
AIRDROP_AMOUNT_SOL = ACCOUNT_CREATION_PRICE_SOL / 2


class FailedAttempts(BaseDB):
    def __init__(self) -> None:
        BaseDB.__init__(self, 'failed_airdrop_attempts')

    def airdrop_failed(self, eth_address, reason):
        with self._conn.cursor() as cur:
            cur.execute(f'''
            INSERT INTO {self._table_name} (attempt_time, eth_address, reason)
            VALUES ({datetime.now().timestamp()}, '{eth_address}', '{reason}')
            ''')


class AirdropReadySet(BaseDB):
    def __init__(self):
        BaseDB.__init__(self, 'airdrop_ready')

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


@logged_group("neon.Airdropper")
class Airdropper(IndexerBase):
    def __init__(self,
                 solana_url,
                 pyth_mapping_account: PublicKey,
                 faucet_url = '',
                 wrapper_whitelist = 'ANY',
                 neon_decimals = 9,
                 pp_solana_url = None,
                 max_conf = 0.1): # maximum confidence interval deviation related to price
        self._constants = SQLDict(tablename="constants")

        solana = SolanaInteractor(solana_url)
        last_known_slot = self._constants.get('latest_processed_slot', None)
        IndexerBase.__init__(self, solana, last_known_slot)
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
        self.pyth_client = PythNetworkClient(SolanaInteractor(pp_solana_url))
        self.neon_decimals = neon_decimals
        self.max_conf = Decimal(max_conf)
        self.session = requests.Session()

        self.sol_price_usd = None
        self.airdrop_amount_usd = None
        self.airdrop_amount_neon = None
        self.last_update_pyth_mapping = None
        self.max_update_pyth_mapping_int = 60 * 60  # update once an hour

    @staticmethod
    def get_current_time():
        return datetime.now().timestamp()

    def try_update_pyth_mapping(self):
        current_time = self.get_current_time()
        if self.last_update_pyth_mapping is None or self.last_update_pyth_mapping - current_time > self.max_update_pyth_mapping_int:
            try:
                self.pyth_client.update_mapping(self.pyth_mapping_account)
                self.last_update_pyth_mapping = current_time
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning(f'Failed to update pyth.network mapping account data ' +
                             f'{type(err)}, Error: {err}, Traceback: {err_tb}')
                return False

        return True

    # helper function checking if given contract address is in whitelist
    def is_allowed_wrapper_contract(self, contract_addr):
        if self.wrapper_whitelist == 'ANY':
            return True
        return contract_addr in self.wrapper_whitelist


    # helper function checking if given 'create account' corresponds to 'approve' instruction
    def check_create_approve_instr(self, account_keys, create_acc, approve):
        # Must use the same Ethereum account
        if account_keys[create_acc['accounts'][2]] != account_keys[approve['accounts'][1]]:
            return False
        
        # Must use the same Operator account
        if account_keys[create_acc['accounts'][0]] != account_keys[approve['accounts'][2]]:
            return False
        return True

    # helper function checking if given 'approve' corresponds to 'call' instruction
    def check_create_approve_call_instr(self, account_keys, create_acc, approve, call):
        # Must use the same Operator account
        if account_keys[approve['accounts'][2]] != account_keys[call['accounts'][1]]:
            return False

        data = base58.b58decode(call['data'])
        caller = data[5:25]
        erc20 = data[90:122]
        method_id = data[122:126]
        source_token = data[126:158]


        created_account = base58.b58decode(create_acc['data'])[1:][:20]
        if created_account != caller:
            self.debug(f"Created account {created_account.hex()} and caller {caller.hex()} are different")
            return False

        sol_caller, _ = PublicKey.find_program_address([b"\1", caller], PublicKey(EVM_LOADER_ID))
        if PublicKey(account_keys[approve['accounts'][1]]) != sol_caller:
            self.debug(f"account_keys[approve['accounts'][1]] != sol_caller")
            return False

        # CreateERC20TokenAccount instruction must use ERC20-wrapper from whitelist
        if not self.is_allowed_wrapper_contract("0x" + erc20.hex()):
            self.debug(f"{erc20.hex()} Is not whitelisted ERC20 contract")
            return False

        if method_id != b'\\\xa3\xe1\xe9':
            return False

        if base58.b58decode(account_keys[approve['accounts'][0]]) != source_token:
            self.debug(f"Claim token account {account_keys[approve['accounts'][0]]} != approve token account {source_token.hex()}")
            return False

        return True

    def airdrop_to(self, eth_address, airdrop_galans):
        self.info(f"Airdrop {airdrop_galans} Galans to address: {eth_address}")
        json_data = { 'wallet': eth_address, 'amount': airdrop_galans }
        resp = self.session.post(self.faucet_url + '/request_neon_in_galans', json=json_data)
        if not resp.ok:
            self.warning(f'Failed to airdrop: {resp.status_code}')
            return False

        return True

    def process_trx_airdropper_mode(self, trx):
        if check_error(trx):
            return
        
        self.debug(f"Processing transaction: {trx}")
        # helper function finding all instructions that satisfies predicate
        def find_instructions(instructions, predicate):
            return [(number, instr) for number, instr in instructions if predicate(instr)]

        def find_inner_instructions(trx, instr_idx, predicate):
            inner_insturctions = None
            for entry in trx['meta']['innerInstructions']:
                if entry['index'] == instr_idx:
                    inner_insturctions = entry['instructions']
                    break

            if inner_insturctions is None:
                self.debug(f'Inner instructions for instruction {instr_idx} not found')
                return []

            return [instruction for instruction in inner_insturctions if predicate(instruction)]

        
        def isRequiredInstruction(instr, req_program_id, req_tag_id):
            return account_keys[instr['programIdIndex']] == req_program_id \
                and base58.b58decode(instr['data'])[0] == req_tag_id


        account_keys = trx["transaction"]["message"]["accountKeys"]
        instructions = [(number, entry) for number, entry in enumerate(trx['transaction']['message']['instructions'])]

        # Finding instructions specific for airdrop.
        # Airdrop triggers on sequence:
        # neon.CreateAccount -> token.Approve -> neon.callFromRawEthereumTrx (call claim method of ERC20)
        # Additionaly:
        # call instruction internally must:
        #   1. Create token account (token.init_v2)
        #   2. Transfer tokens (token.transfer)
        # First: select all instructions that can form such chains
        predicate = lambda instr: isRequiredInstruction(instr, EVM_LOADER_ID, EVM_LOADER_CREATE_ACC)
        create_acc_list = find_instructions(instructions, predicate)
        self.debug(f'create_acc_list: {create_acc_list}')

        predicate = lambda  instr: isRequiredInstruction(instr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', SPL_TOKEN_APPROVE)
        approve_list = find_instructions(instructions, predicate)
        self.debug(f'approve_list: {approve_list}')

        predicate = lambda  instr: isRequiredInstruction(instr, EVM_LOADER_ID, EVM_LOADER_CALL_FROM_RAW_TRX)
        call_list = find_instructions(instructions, predicate)
        self.debug(f'call_list: {call_list}')

        # Second: Find exact chains of instructions in sets created previously
        for _, create_acc in create_acc_list:
            for _, approve in approve_list:
                if not self.check_create_approve_instr(account_keys, create_acc, approve):
                    self.debug(f'check_create_approve_instr failed')
                    continue
                for call_idx, call in call_list:
                    if not self.check_create_approve_call_instr(account_keys, create_acc, approve, call):
                        self.debug(f'check_create_approve_call_instr failed')
                        continue

                    predicate = lambda  instr: isRequiredInstruction(instr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', SPL_TOKEN_INIT_ACC_2)
                    init_token2_list = find_inner_instructions(trx, call_idx, predicate)

                    self.debug(f'init_token2_list = {init_token2_list}')

                    predicate = lambda  instr: isRequiredInstruction(instr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', SPL_TOKEN_TRANSFER)
                    token_transfer_list = find_inner_instructions(trx, call_idx, predicate)

                    self.debug(f'token_transfer_list = {token_transfer_list}')

                    if len(init_token2_list) > 0 and len(token_transfer_list) > 0:
                        self.schedule_airdrop(create_acc)

    def get_sol_usd_price(self):
        should_reload = self.always_reload_price
        if not should_reload:
            if self.recent_price is None or self.recent_price['valid_slot'] < self.current_slot:
                should_reload = True

        if should_reload:
            try:
                self.recent_price = self.pyth_client.get_price('Crypto.SOL/USD')
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning(f'Exception occured when reading price ' +
                             f'{type(err)}, Error: {err}, Traceback: {err_tb}')
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
        eth_address = "0x" + bytearray(base58.b58decode(create_acc['data'])[1:][:20]).hex()
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
            if eth_address in self.airdrop_scheduled:
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
        for slot, _, trx in self.transaction_receipts.get_txs(self.latest_processed_slot):
            max_slot = max(max_slot, slot)
            if trx['transaction']['message']['instructions'] is not None:
                self.process_trx_airdropper_mode(trx)
        self.latest_processed_slot = max(self.latest_processed_slot, max_slot)
        self._constants['latest_processed_slot'] = self.latest_processed_slot
