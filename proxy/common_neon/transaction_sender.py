from __future__ import annotations

import abc
import json
import math
import os
import time
import base58
import sha3
import traceback
import multiprocessing

from logged_groups import logged_group
from typing import NamedTuple, Optional

from solana.transaction import AccountMeta, Transaction, PublicKey
from solana.blockhash import Blockhash
from solana.account import Account as SolanaAccount
from solana.rpc.api import Client as SolanaClient

from .address import accountWithSeed, getTokenAddr
from .constants import STORAGE_SIZE, EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG, ACCOUNT_SEED_VERSION
from .emulator_interactor import call_emulated
from .neon_instruction import NeonInstruction as NeonIxBuilder
from .solana_interactor import COMPUTATION_BUDGET_EXCEEDED
from .solana_interactor import SolanaInteractor, check_for_errors, check_if_accounts_blocked
from .solana_interactor import check_if_big_transaction, check_if_program_exceeded_instructions
from .solana_interactor import get_error_definition_from_receipt, check_if_storage_is_empty_error
from .solana_interactor import check_if_blockhash_notfound
from ..common_neon.eth_proto import Trx as EthTx
from ..environment import RETRY_ON_FAIL, EVM_LOADER_ID, PERM_ACCOUNT_LIMIT
from ..indexer.utils import NeonTxResultInfo, NeonTxInfo
from ..indexer.indexer_db import IndexerDB, NeonPendingTxInfo
from ..environment import get_solana_accounts
from ..common_neon.account_whitelist import AccountWhitelist


class SolanaTxError(Exception):
    def __init__(self, receipt):
        self.result = receipt
        error = get_error_definition_from_receipt(receipt)
        if isinstance(error, list) and isinstance(error[1], str):
            super().__init__(str(error[1]))
        else:
            super().__init__('Unknown error')


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
        self.size = 256
        self.balance = 0

    def _create_account(self):
        assert self.balance > 0
        return self.s.builder.make_trx_with_create_and_airdrop(self._address)

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
        self.size = account_desc['code_size'] + 2048

    def _create_account(self):
        assert self.sol_account
        return self.s.builder.make_trx_with_create_and_airdrop(self._address, self.sol_account)

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
        self.size = account_desc['code_size'] + 2048

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
        self.storage = None
        self.holder = None

    def public_key(self) -> PublicKey:
        return self.signer.public_key()


@logged_group("neon.Proxy")
class OperatorResourceList:
    # These variables are global for class, they will be initialized one time
    _manager = multiprocessing.Manager()
    _free_resource_list_glob = _manager.list()
    _resource_list_len_glob = multiprocessing.Value('i', 0)
    _resource_list = []

    def __init__(self, sender: NeonTxSender):
        self._s = sender
        self._resource = None

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

        with self._resource_list_len_glob.get_lock():
            if self._resource_list_len_glob.value != 0:
                return True

            for idx in range(len(self._resource_list)):
                self._free_resource_list_glob.append(idx)

            self._resource_list_len_glob.value = len(self._resource_list)
            if self._resource_list_len_glob.value == 0:
                raise RuntimeError('No resources!')

    def init_resource_info(self) -> OperatorResourceInfo:
        if self._resource:
            return self._resource

        self._init_resource_list()

        timeout = 0.01
        for i in range(400_000):  # 10'000 blocks!
            if i > 0:
                if i % 40 == 0:  # one block time
                    self.debug(f'Waiting for a free operator resource ({i * timeout})...')
                time.sleep(timeout)

            with self._resource_list_len_glob.get_lock():
                if self._resource_list_len_glob.value == 0:
                    raise RuntimeError('No resources!')
                elif len(self._free_resource_list_glob) == 0:
                    continue
                idx = self._free_resource_list_glob.pop(0)

            self._resource = self._resource_list[idx]
            self._s.set_resource(self._resource)
            if not self._init_perm_accounts():
                self._s.clear_resouce()
                continue

            rid = self._resource.rid
            opkey = str(self._resource.public_key())
            self.debug(f'Resource is selected: {opkey}:{rid}')
            return self._resource

        raise RuntimeError('Timeout on waiting a free operator resource!')

    def _init_perm_accounts(self) -> bool:
        if self._resource and self._resource.storage and self._resource.holder:
            return True

        rid = self._resource.rid

        aid = rid.to_bytes(math.ceil(rid.bit_length() / 8), 'big')
        seed_list = [prefix + aid for prefix in [b"storage", b"holder"]]
        try:
            storage, holder = self._create_perm_accounts(seed_list)
            self._resource.storage = storage
            self._resource.holder = holder
            return True
        except Exception as err:
            self._resource_list_len_glob.value -= 1
            opkey = str(self._resource.public_key())
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f"Fail to init accounts for resource {opkey}:{rid}, err({err}): {err_tb}")
            return False

    def _create_perm_accounts(self, seed_list):
        tx = Transaction()

        stage_list = [NeonCreatePermAccount(self._s, seed, STORAGE_SIZE) for seed in seed_list]
        account_list = [s.sol_account for s in stage_list]
        info_list = self._s.solana.get_multiple_accounts_info(account_list)
        balance = self._s.solana.get_multiple_rent_exempt_balances_for_size([STORAGE_SIZE])[0]
        for account, stage in zip(info_list, stage_list):
            if not account:
                stage.balance = balance
                stage.build()
                tx.add(stage.tx)
            elif account.lamports < balance:
                raise RuntimeError(f"insufficient balance")
            elif PublicKey(account.owner) != PublicKey(EVM_LOADER_ID):
                raise RuntimeError(f"wrong owner")
            elif account.tag not in {EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG}:
                raise RuntimeError(f"not empty, not finalized")

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
        self._s.clear_resouce()

        rid = resource.rid
        opkey = str(resource.public_key())

        if (not resource.storage) or (not resource.holder):
            self.warning(f"Skip freeing bad accounts for resource {opkey}:{rid}")
            return

        info_list = self._s.solana.get_multiple_accounts_info([resource.storage, resource.holder])
        for account in info_list:
            if account.tag not in {EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG}:
                self.error(f"Not empty/finalized accounts for resource {opkey}:{rid}")
                return

        self._free_resource_list_glob.append(resource.idx)


def EthMeta(pubkey, is_writable) -> AccountMeta:
    """The difference with AccountMeta that is_signer = False"""
    return AccountMeta(pubkey=pubkey, is_signer=False, is_writable=is_writable)


@logged_group("neon.Proxy")
class NeonTxSender:
    def __init__(self, db: IndexerDB, client: SolanaClient, whitelist: AccountWhitelist, eth_tx: EthTx, steps: int):
        self._db = db
        self._whitelist = whitelist
        self.eth_tx = eth_tx
        self.steps = steps
        self.solana = SolanaInteractor(client)
        self._resource_list = OperatorResourceList(self)
        self.resource = None
        self.operator_key = None
        self.builder = None

        self._pending_tx = None

        self.tx_sender = eth_tx.sender()
        self.deployed_contract = eth_tx.contract()
        self.steps_emulated = 0

        self.create_account_tx = Transaction()
        self.account_txs_name = ''
        self._resize_contract_list = []
        self._create_account_list = []
        self._eth_meta_list = []

    def execute(self) -> NeonTxResultInfo:
        try:
            self._validate_execution()
            self._prepare_execution()
            return self._execute()
        finally:
            self._whitelist.clear_payer()
            self._resource_list.free_resource_info()

    def set_resource(self, resource: Optional[OperatorResourceInfo]):
        self.resource = resource
        self.operator_key = resource.public_key()
        self.builder = NeonIxBuilder(self.operator_key)

    def clear_resouce(self):
        self.resource = None
        self.operator_key = None
        self.builder = None

    def _validate_execution(self):
        # Validate that operator has available resources: operator key, holder/storage accounts
        self._resource_list.init_resource_info()

        # Validate that transaction is not pended
        neon_sign = self.eth_tx.hash_signed().hex()
        operator = f'{str(self.resource.public_key())}:{self.resource.rid}'
        self._pending_tx = NeonPendingTxInfo(neon_sign=neon_sign, slot=0, operator=operator)
        self.pending_tx_into_db(self.solana.get_recent_blockslot())

        # Validate that transaction is allowed
        whitelist = self._whitelist
        whitelist.set_payer(self.resource.signer)
        if not whitelist.has_client_permission(self.tx_sender):
            self.warning(f'Sender account {self.tx_sender} is not allowed to execute transactions')
            raise Exception(f'Sender account {self.tx_sender} is not allowed to execute transactions')

        if (self.deployed_contract is not None) and (not whitelist.has_contract_permission(self.deployed_contract)):
            self.warning(f'Contract account {self.deployed_contract} is not allowed for deployment')
            raise Exception(f'Contract account {self.deployed_contract} is not allowed for deployment')

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
                if (not Strategy.IS_SIMPLE) or (not check_if_program_exceeded_instructions(e)):
                    raise

        self.error(f'No strategy to execute the Neon transaction: {self.eth_tx}')
        raise RuntimeError('No strategy to execute the Neon transaction')

    def pending_tx_into_db(self, slot: int):
        """
        Transaction sender doesn't remove pending transactions!!!
        This protects the neon transaction execution from race conditions, when user tries to send transaction
        multiple time. User can send the same transaction after it complete too.

        Indexer will purge old pending transactions after finalizing slot.
        """
        if self._pending_tx and ((slot - self._pending_tx.slot) > 10):
            self.debug(f'Update pending transaction: diff {slot - self._pending_tx.slot}, set {slot}')
            self._pending_tx.slot = slot
            self._db.pending_transaction(self._pending_tx)

    def _submit_tx_into_db(self, neon_res: NeonTxResultInfo):
        neon_tx = NeonTxInfo()
        neon_tx.init_from_eth_tx(self.eth_tx)
        self._db.submit_transaction(neon_tx, neon_res, [])

    def _prepare_execution(self):
        self._call_emulated()

        # Parse information from the emulator output
        self._parse_accounts_list()
        self._parse_token_list()
        self._parse_solana_list()

        self.debug('metas: ' + ', '.join([f'{m.pubkey, m.is_signer, m.is_writable}' for m in self._eth_meta_list]))

        # Build all instructions
        self._build_txs()

        self.builder.init_eth_trx(self.eth_tx, self._eth_meta_list, self._caller_token)
        self.builder.init_iterative(self.resource.storage, self.resource.holder, self.resource.rid)

    def _call_emulated(self):
        self.debug(f'sender address: {self.tx_sender}')

        if self.deployed_contract:
            dst = 'deploy'
            self.debug(f'deploy contract: 0x{self.deployed_contract}')
        else:
            dst = self.eth_tx.toAddress.hex()
            self.debug(f'destination address 0x{dst}')

        self._emulator_json = call_emulated(
            dst, self.tx_sender, self.eth_tx.callData.hex(), hex(self.eth_tx.value))
        self.debug(f'emulator returns: {json.dumps(self._emulator_json, indent=3)}')

        self.steps_emulated = self._emulator_json['steps_executed']

    def _add_meta(self, pubkey: PublicKey, is_writable: bool, is_signer=False):
        self._eth_meta_list.append(AccountMeta(pubkey=pubkey, is_signer=is_signer, is_writable=is_writable))

    def _parse_accounts_list(self):
        src_address = self.tx_sender
        dst_address = (self.deployed_contract or self.eth_tx.toAddress.hex())
        src_meta_list = []
        dst_meta_list = []

        for account_desc in self._emulator_json['accounts']:
            if account_desc['new']:
                if account_desc['code_size']:
                    stage = NeonCreateContractTxStage(self, account_desc)
                else:
                    stage = NeonCreateAccountTxStage(self, account_desc)
                self._create_account_list.append(stage)
            elif account_desc['code_size'] and (account_desc['code_size_current'] < account_desc['code_size']):
                self._resize_contract_list.append(NeonResizeContractTxStage(self, account_desc))

            eth_address = account_desc['address'][2:]
            sol_account = account_desc["account"]
            sol_contract = account_desc['contract']

            if eth_address == src_address:
                src_meta_list = [EthMeta(sol_account, True)]
                self._caller_token = getTokenAddr(sol_account)
            else:
                meta_list = dst_meta_list if eth_address == dst_address else self._eth_meta_list
                meta_list.append(EthMeta(sol_account, True))
                if sol_contract:
                    meta_list.append(EthMeta(sol_contract, account_desc['writable']))

        self._eth_meta_list = dst_meta_list + src_meta_list + self._eth_meta_list

    def _parse_token_list(self):
        for token_account in self._emulator_json['token_accounts']:
            self._add_meta(token_account['key'], True)
            if token_account['new']:
                self._create_account_list.append(NeonCreateERC20TxStage(self, token_account))

    def _parse_solana_list(self):
        for account_desc in self._emulator_json['solana_accounts']:
            self._add_meta(account_desc['pubkey'], account_desc['is_writable'], account_desc['is_signer'])

    def _build_txs(self):
        all_stages = self._create_account_list + self._resize_contract_list
        if not len(all_stages):
            return

        size_list = list(set([s.size for s in all_stages]))
        balance_list = self.solana.get_multiple_rent_exempt_balances_for_size(size_list)
        balance_map = {size: balance for size, balance in zip(size_list, balance_list)}
        for s in all_stages:
            s.balance = balance_map[s.size]
            s.build()

        for s in self._create_account_list:
            self.create_account_tx.add(s.tx)
        self.account_txs_name = ' + '.join(set([s.NAME for s in all_stages]))

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
class SolTxListSender:
    def __init__(self, sender, tx_list: [Transaction], name: str):
        self._s = sender
        self._name = name

        self._blockhash = None
        self._retry_idx = 0
        self._tx_list = tx_list
        self._bad_block_list = []
        self._blocked_account_list = []
        self._pending_list = []
        self._budget_exceeded_list = []
        self._storage_empty = []

        self._all_list = [self._bad_block_list,
                          self._blocked_account_list,
                          self._budget_exceeded_list,
                          self._pending_list,
                          self._storage_empty]

    def clear(self):
        self._tx_list.clear()
        for lst in self._all_list:
            lst.clear()

    def _get_full_list(self):
        return [tx for lst in self._all_list for tx in lst]

    def send(self) -> SolTxListSender:
        solana = self._s.solana
        eth_tx = self._s.eth_tx
        signer = self._s.resource.signer

        while (self._retry_idx < RETRY_ON_FAIL) and (len(self._tx_list)):
            self._retry_idx += 1
            receipt_list = solana.send_multiple_transactions(signer, self._tx_list, eth_tx, self._name, self)

            for receipt, tx in zip(receipt_list, self._tx_list):
                if check_if_blockhash_notfound(receipt):
                    self._bad_block_list.append(tx)
                elif check_if_accounts_blocked(receipt):
                    self._blocked_account_list.append(tx)
                elif check_for_errors(receipt):
                    if check_if_program_exceeded_instructions(receipt):
                        self._budget_exceeded_list.append(tx)
                    elif check_if_storage_is_empty_error(receipt):
                        self._storage_empty.append(tx)
                    else:
                        raise SolanaTxError(receipt)
                else:
                    self._on_success_send(tx, receipt)

            self.debug(f'retry {self._retry_idx}, ' +
                       f'total receipts {len(receipt_list)}, ' +
                       f'bad blocks {len(self._bad_block_list)}, ' +
                       f'blocked accounts {len(self._blocked_account_list)}, ' +
                       f'budget exceeded {len(self._budget_exceeded_list)}, ' +
                       f'bad storage status: {len(self._storage_empty)}')

            self._on_post_send()

        if len(self._tx_list):
            raise RuntimeError('Run out of attempts to execute transaction')
        return self

    def on_wait_confirm(self, _, slot: int):
        self._s.pending_tx_into_db(slot)

    def _on_success_send(self, tx: Transaction, receipt: {}):
        """Store the last successfully blockhash and set it in _set_tx_blockhash"""
        self._blockhash = tx.recent_blockhash

    def _on_post_send(self):
        if len(self._storage_empty):
            raise RuntimeError('Custom error [0x1, 0x4]')
        elif len(self._budget_exceeded_list):
            raise RuntimeError(COMPUTATION_BUDGET_EXCEEDED)

        if len(self._blocked_account_list):
            time.sleep(0.4)  # one block time

        # force changing of recent_blockhash if Solana doesn't accept the current one
        if len(self._bad_block_list):
            self._blockhash = None

        # resend not-accepted transactions
        self._move_txlist()

    def _set_tx_blockhash(self, tx):
        """Try to keep the branch of block history"""
        tx.recent_blockhash = self._blockhash
        tx.signatures.clear()

    def _move_txlist(self):
        full_list = self._get_full_list()
        self.clear()
        for tx in full_list:
            self._set_tx_blockhash(tx)
            self._tx_list.append(tx)
        if len(self._tx_list):
            self.debug(f' Resend Solana transactions: {len(self._tx_list)}')


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
            if check_if_big_transaction(err):
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
            if self.neon_res.decode(receipt).is_valid():
                self._s.solana.get_measurements(self._name, self._s.eth_tx, receipt)

        super()._on_success_send(tx, receipt)

    def _on_post_send(self):
        if self.neon_res.is_valid():
            self.debug(f'Got the Neon tx result: {self.neon_res}')
            self.clear()
        else:
            super()._on_post_send()


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
            raise RuntimeError(COMPUTATION_BUDGET_EXCEEDED)
        return tx_sender.neon_res


@logged_group("neon.Proxy")
class IterativeNeonTxSender(SimpleNeonTxSender):
    def __init__(self, *args, **kwargs):
        SimpleNeonTxSender.__init__(self, *args, **kwargs)
        self._is_canceled = False

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
        self._strategy.steps >>= 1
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
        else:
            super()._on_success_send(tx, receipt)

    def _on_post_send(self):
        # Result is received
        if self.neon_res.is_valid():
            self.debug(f'Got Neon tx {"cancel" if self._is_canceled else "result"}: {self.neon_res}')
            return self.clear()

        # There is no more retries to send transactions
        if self._retry_idx == RETRY_ON_FAIL:
            if not self._is_canceled:
                self._cancel()
            return

        # The storage has bad structure and the result isn't received! ((
        if len(self._storage_empty):
            raise RuntimeError('Custom error [0x1, 0x4]')

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
        self.steps += 1

    def _validate(self) -> bool:
        return self._validate_notdeploy_tx() and self._validate_txsize()

    def build_tx(self) -> Transaction:
        # generate unique tx
        if self.steps < 50:
            self.steps += 1
        else:
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
        self._tx_idx += 1  # generate unique tx
        return self.s.builder.make_partial_call_or_continue_from_account_data(self.steps, self._tx_idx)

    def _build_preparation_txs(self) -> [Transaction]:
        tx_list = super()._build_preparation_txs()

        # write eth transaction to the holder account
        unsigned_msg = self.s.eth_tx.unsigned_msg()
        msg = self.s.eth_tx.signature()
        msg += len(unsigned_msg).to_bytes(8, byteorder="little")
        msg += unsigned_msg

        offset = 0
        rest = msg
        while len(rest):
            (part, rest) = (rest[:1000], rest[1000:])
            tx_list.append(self.s.builder.make_write_transaction(offset, part))
            offset += len(part)

        if len(self._preparation_txs_name):
            self._preparation_txs_name += ' + '
        self._preparation_txs_name += 'WriteWithHolder'
        return tx_list
