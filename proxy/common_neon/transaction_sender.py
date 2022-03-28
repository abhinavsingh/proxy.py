from __future__ import annotations

import abc
import json
import math
import os
import time
import base58
import sha3
import traceback
import multiprocessing as mp
import ctypes


from datetime import datetime
from logged_groups import logged_group
from typing import Dict, Optional

from solana.transaction import AccountMeta, Transaction, PublicKey
from solana.blockhash import Blockhash
from solana.account import Account as SolanaAccount

from .address import accountWithSeed, EthereumAddress, ether2program
from .constants import STORAGE_SIZE, EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG, ACCOUNT_SEED_VERSION
from .emulator_interactor import call_emulated
from .neon_instruction import NeonInstruction as NeonIxBuilder
from .solana_interactor import SolanaInteractor
from .solana_tx_list_sender import SolTxListSender
from .solana_receipt_parser import SolTxError, SolReceiptParser, Measurements
from .transaction_validator import NeonTxValidator
from ..common_neon.eth_proto import Trx as EthTx
from ..common_neon.utils import NeonTxResultInfo, NeonTxInfo
from ..environment import RETRY_ON_FAIL, EVM_LOADER_ID, PERM_ACCOUNT_LIMIT
from ..environment import MIN_OPERATOR_BALANCE_TO_WARN, MIN_OPERATOR_BALANCE_TO_ERR, RECHECK_RESOURCE_LIST_INTERVAL
from ..environment import HOLDER_MSG_SIZE, CONTRACT_EXTRA_SPACE
from ..memdb.memdb import MemDB, NeonPendingTxInfo
from ..environment import get_solana_accounts
from proxy.common_neon.utils import get_holder_msg


class NeonTxStage(metaclass=abc.ABCMeta):
    NAME = 'UNKNOWN'

    def __init__(self, sender):
        self.s = sender
        self.tx = Transaction()

    def _is_empty(self):
        return not len(self.tx.signatures)

    @abc.abstractmethod
    def build(self):
        pass


class NeonCreateAccountWithSeedStage(NeonTxStage, abc.ABC):
    def __init__(self, sender):
        NeonTxStage.__init__(self, sender)
        self._seed = bytes()
        self._seed_base = bytes()
        self.sol_account = None
        self.size = 0
        self.balance = 0

    def _init_sol_account(self):
        assert len(self._seed_base) > 0

        self._seed = base58.b58encode(self._seed_base)
        self.sol_account = accountWithSeed(self.s.operator_key, self._seed)

    def _create_account_with_seed(self):
        assert len(self._seed) > 0
        assert self.size > 0
        assert self.balance > 0

        return self.s.builder.create_account_with_seed_trx(self.sol_account, self._seed, self.balance, self.size)


@logged_group("neon.Proxy")
class NeonCreatePermAccount(NeonCreateAccountWithSeedStage, abc.ABC):
    NAME = 'createPermAccount'

    def __init__(self, sender, seed_base: bytes, size: int):
        NeonCreateAccountWithSeedStage.__init__(self, sender)
        self._seed_base = seed_base
        self.size = size
        self._init_sol_account()

    def _init_sol_account(self):
        assert len(self._seed_base) > 0
        seed = sha3.keccak_256(self._seed_base).hexdigest()[:32]
        self._seed = bytes(seed, 'utf8')
        self.sol_account = accountWithSeed(self.s.operator_key, self._seed)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create perm account {self.sol_account}')
        self.tx.add(self._create_account_with_seed())


@logged_group("neon.Proxy")
class NeonCreateAccountTxStage(NeonTxStage):
    NAME = 'createNeonAccount'

    def __init__(self, sender, account_desc):
        NeonTxStage.__init__(self, sender)
        self._address = account_desc['address']
        self.size = 95
        self.balance = 0

    def _create_account(self):
        assert self.balance > 0
        return self.s.builder.make_create_eth_account_trx(self._address)

    def build(self):
        assert self._is_empty()
        self.debug(f'Create user account {self._address}')
        self.tx.add(self._create_account())


@logged_group("neon.Proxy")
class NeonCreateERC20TxStage(NeonTxStage, abc.ABC):
    NAME = 'createERC20Account'

    def __init__(self, sender, token_account):
        NeonTxStage.__init__(self, sender)
        self._token_account = token_account
        self.size = 124
        self.balance = 0

    def _create_erc20_account(self):
        assert self.balance > 0
        return self.s.builder.createERC20TokenAccountTrx(self._token_account)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create ERC20 token account: ' +
                   f'key {self._token_account["key"]}, ' +
                   f'owner: {self._token_account["owner"]}, ' +
                   f'contact: {self._token_account["contract"]}, ' +
                   f'mint: {self._token_account["mint"]}')

        self.tx.add(self._create_erc20_account())


@logged_group("neon.Proxy")
class NeonCreateContractTxStage(NeonCreateAccountWithSeedStage, abc.ABC):
    NAME = 'createNeonContract'

    def __init__(self, sender, account_desc):
        NeonCreateAccountWithSeedStage.__init__(self, sender)
        self._account_desc = account_desc
        self._address = account_desc["address"]
        self._seed_base = ACCOUNT_SEED_VERSION + bytes.fromhex(self._address[2:])
        self._init_sol_account()
        self._account_desc['contract'] = self.sol_account
        self.size = account_desc['code_size'] + CONTRACT_EXTRA_SPACE

    def _create_account(self):
        assert self.sol_account
        return self.s.builder.make_create_eth_account_trx(self._address, self.sol_account)

    def build(self):
        assert self._is_empty()

        self.debug(f'Create contact {self._address}: {self.sol_account} (size {self.size})')

        self.tx.add(self._create_account_with_seed())
        self.tx.add(self._create_account())


@logged_group("neon.Proxy")
class NeonResizeContractTxStage(NeonCreateAccountWithSeedStage, abc.ABC):
    NAME = 'resizeNeonContract'

    def __init__(self, sender, account_desc):
        NeonCreateAccountWithSeedStage.__init__(self, sender)
        self._account_desc = account_desc
        self._seed_base = ACCOUNT_SEED_VERSION + os.urandom(20)
        self._init_sol_account()
        # Replace the old code account with the new code account
        self._old_sol_account = account_desc['contract']
        account_desc['contract'] = self.sol_account
        self.size = account_desc['code_size'] + CONTRACT_EXTRA_SPACE

    def _resize_account(self):
        account = self._account_desc['account']
        return self.s.builder.make_resize_instruction(account, self._old_sol_account, self.sol_account, self._seed)

    def build(self):
        assert self._is_empty()

        self.debug(f'Resize contact {self._account_desc["address"]}: ' +
                   f'{self._old_sol_account} (size {self._account_desc["code_size_current"]}) -> ' +
                   f'{self.sol_account} (size {self.size})')

        self.tx.add(self._create_account_with_seed())
        self.tx.add(self._resize_account())


class OperatorResourceInfo:
    def __init__(self, signer: SolanaAccount, rid: int, idx: int):
        self.signer = signer
        self.rid = rid
        self.idx = idx
        self.ether: Optional[EthereumAddress] = None
        self.storage: Optional[PublicKey] = None
        self.holder: Optional[PublicKey] = None

    def public_key(self) -> PublicKey:
        return self.signer.public_key()

    def secret_key(self) -> bytes:
        return self.signer.secret_key()


@logged_group("neon.Proxy")
class OperatorResourceList:
    # These variables are global for class, they will be initialized one time
    _manager = mp.Manager()
    _free_resource_list = _manager.list()
    _bad_resource_list = _manager.list()
    _check_time_resource_list = _manager.list()
    _resource_list_len = mp.Value(ctypes.c_uint, 0)
    _last_checked_time = mp.Value(ctypes.c_ulonglong, 0)
    _resource_list = []

    def __init__(self, sender: NeonTxSender):
        self._s = sender
        self._resource: Optional[OperatorResourceInfo] = None

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _init_resource_list(self):
        if len(self._resource_list):
            return

        idx = 0
        signer_list = get_solana_accounts()
        for rid in range(PERM_ACCOUNT_LIMIT):
            for signer in signer_list:
                info = OperatorResourceInfo(signer=signer, rid=rid, idx=idx)
                self._resource_list.append(info)
                idx += 1

        with self._resource_list_len.get_lock():
            if self._resource_list_len.value != 0:
                return True

            for idx in range(len(self._resource_list)):
                self._free_resource_list.append(idx)
                self._check_time_resource_list.append(0)

            self._resource_list_len.value = len(self._resource_list)
            if self._resource_list_len.value == 0:
                raise RuntimeError('Operator has NO resources!')

    def _recheck_bad_resource_list(self):
        def is_time_come(now, prev_time):
            time_diff = now - prev_time
            return time_diff > RECHECK_RESOURCE_LIST_INTERVAL

        now = self._get_current_time()
        prev_time = self._last_checked_time.value
        if not is_time_come(now, prev_time):
            return prev_time

        with self._last_checked_time.get_lock():
            prev_time = self._last_checked_time.value
            if not is_time_come(now, prev_time):
                return prev_time
            self._last_checked_time.value = now

        with self._resource_list_len.get_lock():
            if not len(self._bad_resource_list):
                return now

            self._resource_list_len.value += len(self._bad_resource_list)
            for idx in self._bad_resource_list:
                self._free_resource_list.append(idx)

            del self._bad_resource_list[:]
        return now

    def init_resource_info(self) -> OperatorResourceInfo:
        if self._resource:
            return self._resource

        self._init_resource_list()
        check_time = self._recheck_bad_resource_list()

        timeout = 0.01
        for i in range(400_000):  # 10'000 blocks!
            if i > 0:
                if i % 40 == 0:  # one block time
                    self.debug(f'Waiting for a free operator resource ({i * timeout})...')
                time.sleep(timeout)

            with self._resource_list_len.get_lock():
                if self._resource_list_len.value == 0:
                    raise RuntimeError('Operator has NO resources!')
                elif len(self._free_resource_list) == 0:
                    continue
                idx = self._free_resource_list.pop(0)

            self._resource = self._resource_list[idx]
            self._s.set_resource(self._resource)
            if not self._init_perm_accounts(check_time):
                self._s.clear_resource()
                continue

            self.debug(f'Resource is selected: {str(self._resource.public_key())}:{self._resource.rid}, ' +
                       f'storage: {str(self._resource.storage)}, ' +
                       f'holder: {str(self._resource.holder)}, ' +
                       f'ether: {str(self._resource.ether)}')
            return self._resource

        raise RuntimeError('Timeout on waiting a free operator resource!')

    def _init_perm_accounts(self, check_time) -> bool:
        opkey = str(self._resource.public_key())
        rid = self._resource.rid

        resource_check_time = self._check_time_resource_list[self._resource.idx]

        if check_time != resource_check_time:
            self._check_time_resource_list[self._resource.idx] = check_time
            self.debug(f'Rechecking of accounts for resource {opkey}:{rid} {resource_check_time} != {check_time}')
        elif self._resource.storage and self._resource.holder and self._resource.ether:
            return True

        aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
        seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]

        try:
            self._validate_operator_balance()

            storage, holder = self._create_perm_accounts(seed_list)
            ether = self._create_ether_account()
            self._resource.ether = ether
            self._resource.storage = storage
            self._resource.holder = holder
            return True
        except Exception as err:
            self._resource_list_len.value -= 1
            self._bad_resource_list.append(self._resource.idx)
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Fail to init accounts for resource {opkey}:{rid}, err({err}): {err_tb}")
            return False

    @staticmethod
    def _min_operator_balance_to_err():
        return MIN_OPERATOR_BALANCE_TO_ERR

    @staticmethod
    def _min_operator_balance_to_warn():
        return MIN_OPERATOR_BALANCE_TO_WARN

    def _validate_operator_balance(self):
        # Validate operator's account has enough SOLs
        sol_balance = self._s.solana.get_sol_balance(self._resource.public_key())
        min_operator_balance_to_err = self._min_operator_balance_to_err()
        rid = self._resource.rid
        opkey = str(self._resource.public_key())
        if sol_balance <= min_operator_balance_to_err:
            self.error(f'Operator account {opkey}:{rid} has NOT enough SOLs; balance = {sol_balance}; ' +
                       f'min_operator_balance_to_err = {min_operator_balance_to_err}')
            raise RuntimeError('Not enough SOLs')

        min_operator_balance_to_warn = self._min_operator_balance_to_warn()
        if sol_balance <= min_operator_balance_to_warn:
            self.warning(f'Operator account {opkey}:{rid} SOLs are running out; balance = {sol_balance}; ' +
                         f'min_operator_balance_to_warn = {min_operator_balance_to_warn}; ' +
                         f'min_operator_balance_to_err = {min_operator_balance_to_err}; ')

    def _create_ether_account(self) -> EthereumAddress:
        rid = self._resource.rid
        opkey = str(self._resource.public_key())

        ether_address = EthereumAddress.from_private_key(self._resource.secret_key())
        solana_address = ether2program(ether_address)[0]

        account_info = self._s.solana.get_account_info(solana_address)
        if account_info is not None:
            self.debug(f"Use existing ether account {str(solana_address)} for resource {opkey}:{rid}")
            return ether_address

        stage = NeonCreateAccountTxStage(self._s, {"address": ether_address})
        stage.balance = self._s.solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0]
        stage.build()

        self.debug(f"Create new ether account {str(solana_address)} for resource {opkey}:{rid}")
        SolTxListSender(self._s, [stage.tx], NeonCreateAccountTxStage.NAME).send()

        return ether_address

    def _create_perm_accounts(self, seed_list):
        tx = Transaction()

        stage_list = [NeonCreatePermAccount(self._s, seed, STORAGE_SIZE) for seed in seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = self._s.solana.get_account_info_list(account_list)
        balance = self._s.solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for idx, account, stage in zip(range(2), info_list, stage_list):
            if not account:
                stage.balance = balance
                stage.build()
                tx.add(stage.tx)
            elif account.lamports < balance:
                raise RuntimeError(f"insufficient balance of {str(stage.sol_account)}")
            elif PublicKey(account.owner) != PublicKey(EVM_LOADER_ID):
                raise RuntimeError(f"wrong owner for: {str(stage.sol_account)}")
            elif (idx == 0) and (account.tag not in {EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG}):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        rid = self._resource.rid
        opkey = str(self._resource.public_key())
        if len(tx.instructions):
            self.debug(f"Create new accounts for resource {opkey}:{rid}")
            SolTxListSender(self._s, [tx], NeonCreatePermAccount.NAME).send()
        else:
            self.debug(f"Use existing accounts for resource {opkey}:{rid}")
        return account_list

    def free_resource_info(self):
        if not self._resource:
            return
        resource = self._resource
        self._resource = None
        self._s.clear_resource()
        self._free_resource_list.append(resource.idx)


@logged_group("neon.Proxy")
class NeonTxSender:
    def __init__(self, db: MemDB, solana: SolanaInteractor, eth_tx: EthTx, steps: int):
        self._db = db
        self.eth_tx = eth_tx
        self.neon_sign = '0x' + eth_tx.hash_signed().hex()
        self.steps = steps
        self.waiter = self
        self.solana = solana
        self._resource_list = OperatorResourceList(self)
        self.resource = None
        self.signer = None
        self.operator_key = None
        self.builder = None

        self._pending_tx = None

        self.eth_sender = '0x' + eth_tx.sender()
        self.deployed_contract = eth_tx.contract()
        if self.deployed_contract:
            self.deployed_contract = '0x' + self.deployed_contract
        self.to_address = eth_tx.toAddress.hex()
        if self.to_address:
            self.to_address = '0x' + self.to_address
        self.steps_emulated = 0

        self.create_account_tx = Transaction()
        self.account_txs_name = ''
        self._resize_contract_list = []
        self._create_account_list = []
        self._eth_meta_dict: Dict[str, AccountMeta] = dict()

        self._neon_tx_validator = NeonTxValidator(self.solana, eth_tx)

    def execute(self) -> NeonTxResultInfo:
        try:
            self._validate_execution()
            self._prepare_execution()
            return self._execute()
        except Exception as e:
            self._neon_tx_validator.extract_ethereum_error(e)
            raise
        finally:
            self._resource_list.free_resource_info()

    def set_resource(self, resource: Optional[OperatorResourceInfo]):
        self.resource = resource
        self.signer = resource.signer
        self.operator_key = resource.public_key()
        self.builder = NeonIxBuilder(self.operator_key)

    def clear_resource(self):
        self.resource = None
        self.operator_key = None
        self.builder = None

    def _validate_execution(self):
        # Validate that operator has available resources: operator key, holder/storage accounts
        self._resource_list.init_resource_info()

        self._validate_pend_tx()
        self._call_emulated()
        self._neon_tx_validator.prevalidate_tx(self.signer, self._emulator_json)

    def _validate_pend_tx(self):
        operator = f'{str(self.resource.public_key())}:{self.resource.rid}'
        self._pending_tx = NeonPendingTxInfo(neon_sign=self.neon_sign, operator=operator, slot=0)
        self._pend_tx_into_db(self.solana.get_recent_blockslot())

    def _execute(self):
        for Strategy in [SimpleNeonTxStrategy, IterativeNeonTxStrategy, HolderNeonTxStrategy]:
            try:
                strategy = Strategy(self)
                if not strategy.is_valid:
                    self.debug(f'Skip strategy {Strategy.NAME}: {strategy.error}')
                    continue

                self.debug(f'Use strategy {Strategy.NAME}')
                neon_res = strategy.execute()
                self._submit_tx_into_db(neon_res)
                return neon_res
            except Exception as e:
                if (not Strategy.IS_SIMPLE) or (not SolReceiptParser(e).check_if_budget_exceeded()):
                    raise

        self.error(f'No strategy to execute the Neon transaction: {self.eth_tx}')
        raise RuntimeError('No strategy to execute the Neon transaction')

    def on_wait_confirm(self, _, slot: int):
        self._pend_tx_into_db(slot)

    def _pend_tx_into_db(self, slot: int):
        """
        Transaction sender doesn't remove pending transactions!!!
        This protects the neon transaction execution from race conditions, when user tries to send transaction
        multiple time. User can send the same transaction after it complete too.

        Indexer will purge old pending transactions after finalizing slot.
        """
        if self._pending_tx and ((slot - self._pending_tx.slot) > 10):
            self.debug(f'Update pending transaction: diff {slot - self._pending_tx.slot}, set {slot}')
            self._pending_tx.slot = slot
            self._db.pend_transaction(self._pending_tx)

    def _submit_tx_into_db(self, neon_res: NeonTxResultInfo):
        neon_tx = NeonTxInfo()
        neon_tx.init_from_eth_tx(self.eth_tx)
        self._db.submit_transaction(neon_tx, neon_res)

    def _prepare_execution(self):
        # Parse information from the emulator output
        self._parse_accounts_list()
        self._parse_token_list()
        self._parse_solana_list()

        eth_meta_list = list(self._eth_meta_dict.values())
        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in eth_meta_list]))

        # Build all instructions
        self._build_txs()

        self.builder.init_operator_ether(self.resource.ether)
        self.builder.init_eth_trx(self.eth_tx, eth_meta_list)
        self.builder.init_iterative(self.resource.storage, self.resource.holder, self.resource.rid)

    def _call_emulated(self, sender=None):
        src = sender.hex() if sender else self.eth_sender[2:]
        self.debug(f'sender address: 0x{src}')
        if self.deployed_contract:
            dst = 'deploy'
            self.debug(f'deploy contract: {self.deployed_contract}')
        else:
            dst = self.to_address[2:]
            self.debug(f'destination address {self.to_address}')

        self._emulator_json = call_emulated(dst, src, self.eth_tx.callData.hex(), hex(self.eth_tx.value))
        self.debug(f'emulator returns: {json.dumps(self._emulator_json, sort_keys=True)}')

        self.steps_emulated = self._emulator_json['steps_executed']

    def _add_meta(self, pubkey: PublicKey, is_writable: bool):
        key = str(pubkey)
        if key in self._eth_meta_dict:
            self._eth_meta_dict[key].is_writable |= is_writable
        else:
            self._eth_meta_dict[key] = AccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)

    def _parse_accounts_list(self):
        for account_desc in self._emulator_json['accounts']:
            if account_desc['new']:
                if account_desc['code_size']:
                    stage = NeonCreateContractTxStage(self, account_desc)
                    self._create_account_list.append(stage)
                elif account_desc['writable']:
                    stage = NeonCreateAccountTxStage(self, account_desc)
                    self._create_account_list.append(stage)
            elif account_desc['code_size'] and (account_desc['code_size_current'] < account_desc['code_size']):
                self._resize_contract_list.append(NeonResizeContractTxStage(self, account_desc))

            self._add_meta(account_desc['account'], True)
            if account_desc['contract']:
                self._add_meta(account_desc['contract'], account_desc['writable'])

    def _parse_token_list(self):
        for token_account in self._emulator_json['token_accounts']:
            self._add_meta(token_account['key'], True)
            if token_account['new']:
                self._create_account_list.append(NeonCreateERC20TxStage(self, token_account))

    def _parse_solana_list(self):
        for account_desc in self._emulator_json['solana_accounts']:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'])

    def _build_txs(self):
        all_stages = self._create_account_list + self._resize_contract_list
        if not len(all_stages):
            return

        size_list = list(set([s.size for s in all_stages]))
        balance_list = self.solana.get_multiple_rent_exempt_balances_for_size(size_list)
        balance_map = {size: balance for size, balance in zip(size_list, balance_list)}
        name_dict = {}
        for s in all_stages:
            s.balance = balance_map[s.size]
            s.build()
            name_dict.setdefault(s.NAME, 0)
            name_dict[s.NAME] += 1

        for s in self._create_account_list:
            self.create_account_tx.add(s.tx)
        self.account_txs_name = ' + '.join([f'{name}({cnt})' for name, cnt in name_dict.items()])

    def build_account_txs(self, skip_create_accounts=False) -> [Transaction]:
        tx_list = [s.tx for s in self._resize_contract_list]
        if (not skip_create_accounts) and len(self.create_account_tx.instructions):
            tx_list.append(self.create_account_tx)
        return tx_list

    def done_account_txs(self, skip_create_accounts=False):
        self._resize_contract_list.clear()
        if not skip_create_accounts:
            self._create_account_list.clear()
            self.create_account_tx.instructions.clear()


@logged_group("neon.Proxy")
class BaseNeonTxStrategy(metaclass=abc.ABCMeta):
    NAME = 'UNKNOWN STRATEGY'

    def __init__(self, sender: NeonTxSender):
        self.is_valid = False
        self.error = None
        self.s = sender
        self.steps = self.s.steps
        self.is_valid = self._validate()

    @abc.abstractmethod
    def execute(self) -> NeonTxResultInfo:
        return NeonTxResultInfo()

    @abc.abstractmethod
    def build_tx(self) -> Transaction:
        return Transaction()

    @abc.abstractmethod
    def _validate(self) -> bool:
        return True

    def _validate_notdeploy_tx(self) -> bool:
        if self.s.deployed_contract:
            self.error = 'Deploy transaction'
            return False
        return True

    def _validate_txsize(self) -> bool:
        tx = self.build_tx()

        # Predefined blockhash is used only to check transaction size, this transaction won't be send to network
        tx.recent_blockhash = Blockhash('4NCYB3kRT8sCNodPNuCZo8VUh4xqpBQxsxed2wd9xaD4')
        tx.sign(self.s.resource.signer)
        try:
            tx.serialize()
            return True
        except Exception as err:
            if SolReceiptParser(err).check_if_big_transaction():
                self.error = 'Too big transaction size'
                return False
            self.error = str(err)
            raise


@logged_group("neon.Proxy")
class SimpleNeonTxSender(SolTxListSender):
    def __init__(self, strategy: BaseNeonTxStrategy, *args, **kwargs):
        SolTxListSender.__init__(self, *args, **kwargs)
        self._strategy = strategy
        self.neon_res = NeonTxResultInfo()

    def _on_success_send(self, tx: Transaction, receipt: {}):
        if not self.neon_res.is_valid():
            if self.neon_res.decode(self._s.neon_sign, receipt).is_valid():
                Measurements().extract(self._name, receipt)
        super()._on_success_send(tx, receipt)

    def _on_post_send(self):
        if self.neon_res.is_valid():
            self.debug(f'Got Neon tx result: {self.neon_res}')
            self.clear()
        else:
            super()._on_post_send()

            if not len(self._tx_list):
                raise RuntimeError('Run out of attempts to execute transaction')


@logged_group("neon.Proxy")
class SimpleNeonTxStrategy(BaseNeonTxStrategy, abc.ABC):
    NAME = 'CallFromRawEthereumTX'
    IS_SIMPLE = True

    def __init__(self, *args, **kwargs):
        self._skip_create_account = False
        BaseNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        if (not self._validate_steps()) or (not self._validate_notdeploy_tx()):
            return False

        # Attempting to include create accounts instructions into the transaction
        if self._validate_txsize():
            return True

        self._skip_create_account = not self._skip_create_account
        return self._validate_txsize()

    def _validate_steps(self) -> bool:
        if self.s.steps_emulated > self.steps:
            self.error = 'Too big number of EVM steps'
            return False
        return True

    def build_tx(self) -> Transaction:
        tx = Transaction()
        if not self._skip_create_account:
            tx.add(self.s.create_account_tx)
        tx.add(self.s.builder.make_noniterative_call_transaction(len(tx.instructions)))
        return tx

    def execute(self) -> NeonTxResultInfo:
        tx_list = self.s.build_account_txs(not self._skip_create_account)
        if len(tx_list) > 0:
            SolTxListSender(self.s, tx_list, self.s.account_txs_name).send()
            self.s.done_account_txs(self._skip_create_account)

        tx_sender = SimpleNeonTxSender(self, self.s, [self.build_tx()], self.NAME).send()
        if not tx_sender.neon_res.is_valid():
            raise tx_sender.raise_budget_exceeded()
        return tx_sender.neon_res


@logged_group("neon.Proxy")
class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, *args, **kwargs):
        SimpleNeonTxSender.__init__(self, *args, **kwargs)
        self._is_canceled = False
        self._postponed_error_receipt = None

    def _try_lock_accounts(self):
        time.sleep(0.4)  # one block time

        # send one transaction to get lock, and only after that send all others
        tx = self._blocked_account_list.pop()
        self._set_tx_blockhash(tx)
        self._tx_list = [tx]

        # prevent the transaction sending one at a time
        self._pending_list += self._blocked_account_list
        self._blocked_account_list.clear()

    def _cancel(self):
        self.debug(f'Cancel the transaction')
        self.clear()
        self._name = 'CancelWithNonce'
        self._is_canceled = True
        self._retry_idx = 0  # force the cancel sending
        self._tx_list = [self._s.builder.make_cancel_transaction()]

    def _decrease_steps(self):
        self._strategy.steps -= 150
        self.debug(f'Decrease EVM steps to {self._strategy.steps}')
        if self._strategy.steps < 50:
            return self._cancel()

        total_cnt = len(self._get_full_list()) * 2

        self.clear()
        self._tx_list = [self._strategy.build_tx() for _ in range(total_cnt)]

    def _on_success_send(self, tx: Transaction, receipt: {}):
        if self._is_canceled:
            # Transaction with cancel is confirmed
            self.neon_res.canceled(receipt)
            Measurements().extract(self._name, receipt)
        else:
            super()._on_success_send(tx, receipt)

    def _raise_error(self, error=None):
        if self._postponed_error_receipt:
            raise SolTxError(self._postponed_error_receipt)

        assert error is not None
        raise error

    def _on_post_send(self):
        # Result is received
        if self.neon_res.is_valid():
            self.debug(f'Got Neon tx {"cancel" if self._is_canceled else "result"}: {self.neon_res}')
            if self._is_canceled and self._postponed_error_receipt:
                self._raise_error()
            return self.clear()

        if len(self._node_behind_list):
            self.warning(f'Node is behind by {self._slots_behind} slots')
            time.sleep(1)

        # Unknown error happens - cancel the transaction
        if len(self._unknown_error_list):
            if self._is_canceled:
                self._raise_error(SolTxError(self._unknown_error_list[0]))

            self._postponed_error_receipt = self._unknown_error_list[0]
            self._unknown_error_list.clear()
            if self._total_success_cnt:
                return self._cancel()
            self._raise_error()

        # There is no more retries to send transactions
        if self._retry_idx >= RETRY_ON_FAIL:
            if (not self._is_canceled) and (self._total_success_cnt > 0):
                self._cancel()
            self._raise_error(RuntimeError('No more retries to complete transaction!'))

        # Blockhash is changed (((
        if len(self._bad_block_list):
            self._blockhash = None

        # Accounts are blocked, so try to lock them
        if len(self._blocked_account_list):
            return self._try_lock_accounts()

        # Compute budged is exceeded, so decrease EVM steps per iteration
        if len(self._budget_exceeded_list):
            return self._decrease_steps()

        self._move_txlist()

        # if no iterations and no result then add the additional iteration
        if not len(self._tx_list):
            self.debug('No result -> add the additional iteration')
            self._tx_list.append(self._strategy.build_tx())


@logged_group("neon.Proxy")
class IterativeNeonTxStrategy(BaseNeonTxStrategy, abc.ABC):
    NAME = 'PartialCallOrContinueFromRawEthereumTX'
    IS_SIMPLE = False

    def __init__(self, *args, **kwargs):
        BaseNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        return self._validate_notdeploy_tx() and self._validate_txsize() and self._validate_evm_steps()

    def _validate_evm_steps(self):
        if self.s.steps_emulated > (self.s.steps * 25):
            self.error = 'Big number of EVM steps'
            return False
        return True

    def build_tx(self) -> Transaction:
        # generate unique tx
        self.steps -= 1
        return self.s.builder.make_partial_call_or_continue_transaction(self.steps)

    def _build_preparation_txs(self) -> [Transaction]:
        self._preparation_txs_name = self.s.account_txs_name
        return self.s.build_account_txs(False)

    def execute(self) -> NeonTxResultInfo:
        tx_list = self._build_preparation_txs()
        if len(tx_list):
            SolTxListSender(self.s, tx_list, self._preparation_txs_name).send()
            self.s.done_account_txs()

        cnt = math.ceil(self.s.steps_emulated / self.steps)
        cnt = math.ceil(self.s.steps_emulated / (self.steps - cnt)) + 2  # +1 on begin, +1 on end
        tx_list = [self.build_tx() for _ in range(cnt)]
        self.debug(f'Total iterations {len(tx_list)} for {self.s.steps_emulated} ({self.steps}) EVM steps')
        return IterativeNeonTxSender(self, self.s, tx_list, self.NAME).send().neon_res


@logged_group("neon.Proxy")
class HolderNeonTxStrategy(IterativeNeonTxStrategy, abc.ABC):
    NAME = 'ExecuteTrxFromAccountDataIterativeOrContinue'

    def __init__(self, *args, **kwargs):
        self._tx_idx = 0
        IterativeNeonTxStrategy.__init__(self, *args, **kwargs)

    def _validate(self) -> bool:
        return self._validate_txsize()

    def build_tx(self) -> Transaction:
        self._tx_idx += 1
        return self.s.builder.make_partial_call_or_continue_from_account_data(self.steps, self._tx_idx)

    def _build_preparation_txs(self) -> [Transaction]:
        tx_list = super()._build_preparation_txs()

        # write eth transaction to the holder account
        msg = get_holder_msg(self.s.eth_tx)

        offset = 0
        rest = msg
        cnt = 0
        while len(rest):
            (part, rest) = (rest[:HOLDER_MSG_SIZE], rest[HOLDER_MSG_SIZE:])
            tx_list.append(self.s.builder.make_write_transaction(offset, part))
            offset += len(part)
            cnt += 1

        if len(self._preparation_txs_name):
            self._preparation_txs_name += ' + '
        self._preparation_txs_name += f'WriteWithHolder({cnt})'
        return tx_list
