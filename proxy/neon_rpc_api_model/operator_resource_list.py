# from __future__ import annotations
# from __future__ import annotations

import abc
import ctypes
import math
import multiprocessing as mp
import time
import traceback
from datetime import datetime
from typing import Optional, List

import sha3
from logged_groups import logged_group
from solana.account import Account as SolanaAccount
from solana.publickey import PublicKey

from ..common_neon.address import EthereumAddress, ether2program, accountWithSeed
from ..common_neon.compute_budget import TransactionWithComputeBudget
from ..common_neon.constants import STORAGE_SIZE, ACTIVE_STORAGE_TAG, FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG
from ..common_neon.solana_tx_list_sender import SolTxListSender
from ..environment import get_solana_accounts, PERM_ACCOUNT_LIMIT, RECHECK_RESOURCE_LIST_INTERVAL, \
                          MIN_OPERATOR_BALANCE_TO_ERR, MIN_OPERATOR_BALANCE_TO_WARN, EVM_LOADER_ID


## TODO: DIP corruption, get rid of back dependency
# from .transaction_sender import NeonTxSender
from .neon_tx_stages import NeonCancelTxStage, NeonCreateAccountTxStage, NeonCreateAccountWithSeedStage


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

    def __init__(self, sender):
        self._s = sender
        self._solana = sender.solana
        self._builder = sender.builder
        self._resource: Optional[OperatorResourceInfo] = None

    def __enter__(self):
        return self.get_active_resource()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.free_resource_info()

    @staticmethod
    def _get_current_time() -> int:
        return math.ceil(datetime.now().timestamp())

    def _init_resource_list(self):
        if len(self._resource_list):
            return

        idx = 0
        signer_list: List[SolanaAccount] = get_solana_accounts()
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

    def get_active_resource(self) -> OperatorResourceInfo:
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
            if not self._init_perm_accounts(check_time, self._resource):
                self._s.clear_resource()
                continue

            self.debug(f'Resource is selected: {str(self._resource.public_key())}:{self._resource.rid}, ' +
                       f'storage: {str(self._resource.storage)}, ' +
                       f'holder: {str(self._resource.holder)}, ' +
                       f'ether: {str(self._resource.ether)}')
            return self._resource

        raise RuntimeError('Timeout on waiting a free operator resource!')

    def _init_perm_accounts(self, check_time, resource: OperatorResourceInfo) -> bool:
        opkey = str(resource.public_key())
        rid = resource.rid

        resource_check_time = self._check_time_resource_list[resource.idx]

        if check_time != resource_check_time:
            self._check_time_resource_list[resource.idx] = check_time
            self.debug(f'Rechecking of accounts for resource {opkey}:{rid} {resource_check_time} != {check_time}')
        elif resource.storage and resource.holder and resource.ether:
            return True

        aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
        seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]

        try:
            self._validate_operator_balance()

            storage, holder = self._create_perm_accounts(seed_list)
            ether = self._create_ether_account()
            resource.ether = ether
            resource.storage = storage
            resource.holder = holder
            return True
        except Exception as err:
            self._resource_list_len.value -= 1
            self._bad_resource_list.append(resource.idx)
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
        sol_balance = self._solana.get_sol_balance(self._resource.public_key())
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

        account_info = self._solana.get_account_info(solana_address)
        if account_info is not None:
            self.debug(f"Use existing ether account {str(solana_address)} for resource {opkey}:{rid}")
            return ether_address

        stage = NeonCreateAccountTxStage(self._s, {"address": ether_address})
        stage.balance = self._solana.get_multiple_rent_exempt_balances_for_size([stage.size])[0]
        stage.build()

        self.debug(f"Create new ether account {str(solana_address)} for resource {opkey}:{rid}")
        SolTxListSender(self._s, [stage.tx], NeonCreateAccountTxStage.NAME).send(self._resource.signer)

        return ether_address

    def _create_perm_accounts(self, seed_list):
        rid = self._resource.rid
        opkey = str(self._resource.public_key())

        tx = TransactionWithComputeBudget()
        tx_name_list = set()

        stage_list = [NeonCreatePermAccount(self._s, seed, STORAGE_SIZE) for seed in seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = self._solana.get_account_info_list(account_list)
        balance = self._solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for idx, account, stage in zip(range(len(seed_list)), info_list, stage_list):
            if not account:
                self.debug(f"Create new accounts for resource {opkey}:{rid}")
                stage.balance = balance
                stage.build()
                tx_name_list.add(stage.NAME)
                tx.add(stage.tx)
                continue
            elif account.lamports < balance:
                raise RuntimeError(f"insufficient balance of {str(stage.sol_account)}")
            elif PublicKey(account.owner) != PublicKey(EVM_LOADER_ID):
                raise RuntimeError(f"wrong owner for: {str(stage.sol_account)}")
            elif idx != 0:
                continue

            if account.tag == ACTIVE_STORAGE_TAG:
                self.debug(f"Cancel transaction in {str(stage.sol_account)} for resource {opkey}:{rid}")
                cancel_stage = NeonCancelTxStage(self._s, stage.sol_account)
                cancel_stage.build()
                tx_name_list.add(cancel_stage.NAME)
                tx.add(cancel_stage.tx)
            elif account.tag not in (FINALIZED_STORAGE_TAG, EMPTY_STORAGE_TAG):
                raise RuntimeError(f"not empty, not finalized: {str(stage.sol_account)}")

        if len(tx_name_list):
            SolTxListSender(self._s, [tx], ' + '.join(tx_name_list)).send(self._resource.signer)
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
