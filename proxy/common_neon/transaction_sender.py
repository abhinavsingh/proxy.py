import json
import logging
import math
import os
from typing import List
import rlp
import time

from base58 import b58encode
from sha3 import keccak_256
from solana.sysvar import *
from solana.transaction import AccountMeta, Transaction

from proxy.indexer.utils import check_error

from ..core.acceptor.pool import new_acc_id_glob, acc_list_glob

from .address import accountWithSeed, AccountInfo, getTokenAddr
from .constants import STORAGE_SIZE, EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG, ACCOUNT_SEED_VERSION
from .emulator_interactor import call_emulated
from .layouts import ACCOUNT_INFO_LAYOUT
from .neon_instruction import NeonInstruction
from .solana_interactor import SolanaInteractor, check_for_errors,\
    check_if_program_exceeded_instructions, check_if_accounts_blocked, get_logs_from_reciept
from ..environment import EVM_LOADER_ID, RETRY_ON_BLOCKED
from ..plugin.eth_proto import Trx as EthTrx
from ..indexer.utils import NeonTxResultInfo


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class TransactionSender:
    def __init__(self, solana_interactor: SolanaInteractor, eth_trx: EthTrx, steps: int) -> None:
        self.sender = solana_interactor
        self.eth_trx = eth_trx
        self.steps = steps

        self.instruction = NeonInstruction(self.sender.get_operator_key())


    def execute(self):
        self.create_account_list_by_emulate()

        noniterative_executor = self.create_noniterative_executor()

        call_iterative = False
        call_from_holder = False

        if not self.eth_trx.toAddress:
            call_from_holder = True
        else:
            try:
                logger.debug("Try single trx call")
                return noniterative_executor.call_signed_noniterative()
            except Exception as err:
                logger.debug(str(err))
                errStr = str(err)
                if "Program failed to complete" in errStr or "Computational budget exceeded" in errStr:
                    logger.debug("Program exceeded instructions")
                    if self.steps_emulated / self.steps > self.steps / 2:
                        """
                            An iterative call from instruction data can be performed in batches only
                            with a change in the number of steps in the iteration.
                            Each next iteration the number of steps decreases.
                            Thus, starting from a certain number of steps,
                            it is appropriate to use a call from the account data,
                            since there the number of steps is unchanged.
                        """
                        call_from_holder = True
                    else:
                        call_iterative = True
                elif str(err).startswith("transaction too large:"):
                    logger.debug("Transaction too large, call call_signed_with_holder_acc():")
                    call_from_holder = True
                else:
                    raise

        self.init_perm_accs()
        iterative_executor = self.create_iterative_executor()
        try:
            if call_iterative:
                try:
                    return iterative_executor.call_signed_iterative_combined()
                except Exception as err:
                    logger.debug(str(err))
                    if str(err).startswith("transaction too large:"):
                        logger.debug("Transaction too large, call call_signed_with_holder_acc():")
                        call_from_holder = True
                    else:
                        raise

            if call_from_holder:
                return iterative_executor.call_signed_with_holder_combined()
        finally:
            self.free_perm_accs()


    def create_noniterative_executor(self):
        self.instruction.init_eth_trx(self.eth_trx, self.eth_accounts, self.caller_token)
        return NoniterativeTransactionSender(self.sender, self.instruction, self.create_acc_trx, self.eth_trx)


    def create_iterative_executor(self):
        self.instruction.init_iterative(self.storage, self.holder, self.perm_accs_id)
        return IterativeTransactionSender(self.sender, self.instruction, self.create_acc_trx, self.eth_trx, self.steps, self.steps_emulated)


    def init_perm_accs(self):
        while True:
            with new_acc_id_glob.get_lock():
                try:
                    self.perm_accs_id = acc_list_glob.pop(0)
                except IndexError:
                    self.perm_accs_id = new_acc_id_glob.value
                    new_acc_id_glob.value += 1

            logger.debug("LOCK RESOURCES {}".format(self.perm_accs_id))

            acc_id_bytes = self.perm_accs_id.to_bytes((self.perm_accs_id.bit_length() + 7) // 8, 'big')

            storage_seed = keccak_256(b"storage" + acc_id_bytes).hexdigest()[:32]
            storage_seed = bytes(storage_seed, 'utf8')

            holder_seed = keccak_256(b"holder" + acc_id_bytes).hexdigest()[:32]
            holder_seed = bytes(holder_seed, 'utf8')

            try:
                self.storage, self.holder = self.create_multiple_accounts_with_seed(
                        seeds=[storage_seed, holder_seed],
                        sizes=[STORAGE_SIZE, STORAGE_SIZE]
                    )
            except Exception as err:
                logger.warn("Account is locked err({}) id({}) owner({})".format(str(err), self.perm_accs_id, self.sender.get_operator_key()))
            else:
                break


    def free_perm_accs(self):
        logger.debug("FREE RESOURCES {}".format(self.perm_accs_id))
        with new_acc_id_glob.get_lock():
            acc_list_glob.append(self.perm_accs_id)


    def create_account_with_seed(self, seed, storage_size):
        account = accountWithSeed(self.sender.get_operator_key(), seed)

        if self.sender.get_sol_balance(account) == 0:
            minimum_balance = self.sender.get_multiple_rent_exempt_balances_for_size([storage_size])[0]
            logger.debug("Minimum balance required for account {}".format(minimum_balance))

            trx = Transaction()
            trx.add(self.instruction.create_account_with_seed_trx(account, seed, minimum_balance, storage_size))
            self.sender.send_transaction(trx, eth_trx=self.eth_trx, reason='createAccountWithSeed')

        return account


    def create_multiple_accounts_with_seed(self, seeds: List[bytes], sizes: List[int]) -> List[PublicKey]:
        accounts = list(map(lambda seed: accountWithSeed(self.sender.get_operator_key(), seed), seeds))
        accounts_info = self.sender.get_multiple_accounts_info(accounts)
        minimum_balances = self.sender.get_multiple_rent_exempt_balances_for_size(sizes)

        trx = Transaction()

        for account_key, account_info, seed, minimum_balance, storage_size in zip(accounts, accounts_info, seeds, minimum_balances, sizes):
            if account_info is None:
                logger.debug("Minimum balance required for account {}".format(minimum_balance))
                trx.add(self.instruction.create_account_with_seed_trx(account_key, seed, minimum_balance, storage_size))
            else:
                if account_info.lamports < minimum_balance:
                    raise Exception("insufficient balance")
                if PublicKey(account_info.owner) != PublicKey(EVM_LOADER_ID):
                    raise Exception("wrong owner")
                if account_info.tag not in {EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG}:
                    raise Exception("not empty, not finalized")

        if len(trx.instructions) > 0:
            self.sender.send_transaction(trx, eth_trx=self.eth_trx, reason='createAccountWithSeed')

        return accounts


    def create_account_list_by_emulate(self):
        sender_ether = bytes.fromhex(self.eth_trx.sender())
        add_keys_05 = []
        self.create_acc_trx = Transaction()

        if not self.eth_trx.toAddress:
            to_address_arg = "deploy"
            to_address = keccak_256(rlp.encode((bytes.fromhex(self.eth_trx.sender()), self.eth_trx.nonce))).digest()[-20:]
        else:
            to_address_arg = self.eth_trx.toAddress.hex()
            to_address = self.eth_trx.toAddress

        logger.debug("send_addr: %s", self.eth_trx.sender())
        logger.debug("dest_addr: %s", to_address.hex())

        output_json = call_emulated(to_address_arg, sender_ether.hex(), self.eth_trx.callData.hex(), hex(self.eth_trx.value))
        logger.debug("emulator returns: %s", json.dumps(output_json, indent=3))

        # resize storage account
        resize_instr = []
        for acc_desc in output_json["accounts"]:
            if acc_desc["new"] == False:
                if acc_desc["code_size_current"] is not None and acc_desc["code_size"] is not None:
                    if acc_desc["code_size"] > acc_desc["code_size_current"]:
                        code_size = acc_desc["code_size"] + 2048
                        seed = b58encode(ACCOUNT_SEED_VERSION + os.urandom(20))
                        code_account_new = accountWithSeed(self.sender.get_operator_key(), seed)

                        logger.debug("creating new code_account with increased size %s", code_account_new)
                        self.create_account_with_seed(seed, code_size)
                        logger.debug("resized account is created %s", code_account_new)

                        resize_instr.append(self.instruction.make_resize_instruction(acc_desc, code_account_new, seed))
                        # replace code_account
                        acc_desc["contract"] = code_account_new

        for instr in resize_instr:
            logger.debug("code and storage migration, account %s from  %s to %s", instr.keys[0].pubkey, instr.keys[1].pubkey, instr.keys[2].pubkey)

            tx = Transaction().add(instr)
            success = False
            count = 0

            while count < 2:
                logger.debug("attemt: %d", count)

                self.sender.send_transaction(tx, eth_trx=self.eth_trx, reason='resize_storage_account')
                info = self.sender._getAccountData(instr.keys[0].pubkey, ACCOUNT_INFO_LAYOUT.sizeof())
                info_data = AccountInfo.frombytes(info)
                if info_data.code_account == instr.keys[2].pubkey:
                    success = True
                    logger.debug("successful code and storage migration, %s", instr.keys[0].pubkey)
                    break
                # wait for unlock account
                time.sleep(1)
                count = count+1

            if success == False:
                raise Exception("Can't resize storage account. Account is blocked {}".format(instr.keys[0].pubkey))

        for acc_desc in output_json["accounts"]:
            address = bytes.fromhex(acc_desc["address"][2:])

            code_account = None
            code_account_writable = False
            if acc_desc["new"]:
                logger.debug("Create solana accounts for %s: %s %s", acc_desc["address"], acc_desc["account"], acc_desc["contract"])
                if acc_desc["code_size"]:
                    seed = b58encode(ACCOUNT_SEED_VERSION+address)
                    code_account = accountWithSeed(self.sender.get_operator_key(), seed)
                    logger.debug("     with code account %s", code_account)
                    code_size = acc_desc["code_size"] + 2048
                    code_account_balance = self.sender.get_multiple_rent_exempt_balances_for_size([code_size])[0]
                    self.create_acc_trx.add(self.instruction.create_account_with_seed_trx(code_account, seed, code_account_balance, code_size))
                    # add_keys_05.append(AccountMeta(pubkey=code_account, is_signer=False, is_writable=acc_desc["writable"]))
                    code_account_writable = acc_desc["writable"]

                create_trx = self.instruction.make_trx_with_create_and_airdrop(address, code_account)
                self.create_acc_trx.add(create_trx)

            if address == to_address:
                contract_sol = PublicKey(acc_desc["account"])
                if acc_desc["new"]:
                    code_sol = code_account
                    code_writable = code_account_writable
                else:
                    if acc_desc["contract"] != None:
                        code_sol = PublicKey(acc_desc["contract"])
                        code_writable = acc_desc["writable"]
                    else:
                        code_sol = None
                        code_writable = None

            if address == sender_ether:
                sender_sol = PublicKey(acc_desc["account"])

            if address != to_address and address != sender_ether:
                add_keys_05.append(AccountMeta(pubkey=acc_desc["account"], is_signer=False, is_writable=True))
                if acc_desc["new"]:
                    if code_account:
                        add_keys_05.append(AccountMeta(pubkey=code_account, is_signer=False, is_writable=code_account_writable))
                else:
                    if acc_desc["contract"]:
                        add_keys_05.append(AccountMeta(pubkey=acc_desc["contract"], is_signer=False, is_writable=acc_desc["writable"]))


        for token_account in output_json["token_accounts"]:
            add_keys_05.append(AccountMeta(pubkey=PublicKey(token_account["key"]), is_signer=False, is_writable=True))

            if token_account["new"]:
                self.create_acc_trx.add(self.instruction.createERC20TokenAccountTrx(token_account))

        for account_meta in output_json["solana_accounts"]:
            add_keys_05.append(AccountMeta(pubkey=PublicKey(account_meta["pubkey"]), is_signer=account_meta["is_signer"], is_writable=account_meta["is_writable"]))

        self.caller_token = getTokenAddr(PublicKey(sender_sol))

        self.eth_accounts = [
                AccountMeta(pubkey=contract_sol, is_signer=False, is_writable=True),
            ] + ([AccountMeta(pubkey=code_sol, is_signer=False, is_writable=code_writable)] if code_sol != None else []) + [
                AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
            ] + add_keys_05

        self.steps_emulated = output_json["steps_executed"]


class NoniterativeTransactionSender:
    def __init__(self, solana_interactor: SolanaInteractor, neon_instruction: NeonInstruction, create_acc_trx: Transaction, eth_trx: EthTrx):
        self.sender = solana_interactor
        self.instruction = neon_instruction
        self.create_acc_trx = create_acc_trx
        self.eth_trx = eth_trx


    def call_signed_noniterative(self):
        call_txs_05 = Transaction()
        if len(self.create_acc_trx.instructions) > 0:
            call_txs_05.add(self.create_acc_trx)
        call_txs_05.add(self.instruction.make_noniterative_call_transaction(len(call_txs_05.instructions)))

        for _i in range(RETRY_ON_BLOCKED):
            result = self.sender.send_measured_transaction(call_txs_05, self.eth_trx, 'CallFromRawEthereumTX')

            if check_for_errors(result):
                if check_if_program_exceeded_instructions(result):
                    raise Exception("Program failed to complete")
                elif check_if_accounts_blocked(result):
                    time.sleep(0.5)
                    continue
                else:
                    raise Exception(json.dumps(result['meta']))
            else:
                return (NeonTxResultInfo(result), result['transaction']['signatures'][0])


class IterativeTransactionSender:
    CONTINUE_REGULAR = 'ContinueV02'
    CONTINUE_COMBINED = 'PartialCallOrContinueFromRawEthereumTX'
    CONTINUE_HOLDER_COMB = 'ExecuteTrxFromAccountDataIterativeOrContinue'

    class ContinueReturn:
        def __init__(self, success_signature, neon_res, none_receipts, logs, found_errors, try_one_step, retry_on_blocked, step_count):
            self.success_signature = success_signature
            self.neon_res = neon_res
            self.none_receipts = none_receipts
            self.logs = logs
            self.found_errors = found_errors
            self.try_one_step = try_one_step
            self.retry_on_blocked = retry_on_blocked
            self.step_count = step_count


    def __init__(self, solana_interactor: SolanaInteractor, neon_instruction: NeonInstruction, create_acc_trx: Transaction, eth_trx: EthTrx, steps: int, steps_emulated: int):
        self.sender = solana_interactor
        self.instruction = neon_instruction
        self.create_acc_trx = create_acc_trx
        self.eth_trx = eth_trx
        self.steps = steps
        self.steps_emulated = steps_emulated
        self.success_steps = 0
        self.instruction_type = self.CONTINUE_REGULAR


    def call_signed_iterative_combined(self):
        if len(self.create_acc_trx.instructions) > 0:
            create_accounts_siganture = self.sender.send_transaction_unconfirmed(self.create_acc_trx)
            self.sender.confirm_multiple_transactions([create_accounts_siganture])
            self.create_acc_trx = Transaction()

        self.instruction_type = self.CONTINUE_COMBINED
        return self.call_continue()


    def call_signed_with_holder_combined(self):
        if len(self.create_acc_trx.instructions) > 0:
            self.write_to_holder_account_trx(self.create_acc_trx)
            self.create_acc_trx = Transaction()
        else:
            self.write_to_holder_account_trx()

        self.instruction_type = self.CONTINUE_HOLDER_COMB
        return self.call_continue()


    def write_to_holder_account_trx(self, create_acc_trx = None) -> List[Transaction]:
        logger.debug('write_trx_to_holder_account')
        msg = self.eth_trx.signature() + len(self.eth_trx.unsigned_msg()).to_bytes(8, byteorder="little") + self.eth_trx.unsigned_msg()

        offset = 0
        rest = msg
        write_trxs = []
        if create_acc_trx is not None:
            write_trxs.append(create_acc_trx)
        while len(rest):
            (part, rest) = (rest[:1000], rest[1000:])
            trx = self.instruction.make_write_transaction(offset, part)
            write_trxs.append(trx)
            offset += len(part)

        while len(write_trxs) > 0:
            (trxs, write_trxs) = (write_trxs[:20], write_trxs[20:])
            logger.debug(f'write_trxs {len(write_trxs)} trxs {len(trxs)}')

            while len(trxs) > 0:
                logger.debug(f'write {len(trxs)} trxs')
                receipts = self.sender.send_multiple_transactions_unconfirmed(trxs)
                results = self.sender.collect_results(receipts, eth_trx=self.eth_trx, reason='WriteHolder')

                success_trxs = []
                for result, trx in zip(results, trxs):
                    if result is not None:
                        success_trxs.append(trx)
                trxs = [trx for trx in trxs if trx not in success_trxs]


    def call_continue(self):
        none_receipts = []
        while True:
            logs = []
            try_one_step = False
            found_errors = False

            logger.debug(f"Send pack of combined: {self.instruction_type}")
            trxs = []
            for index in range(self.steps_count()):
                trxs.append(self.make_combined_trx(self.steps, index))

            continue_result = self.send_and_confirm_continue(trxs, none_receipts)

            if continue_result.success_signature is not None:
                return (continue_result.neon_res, continue_result.success_signature)
            none_receipts = continue_result.none_receipts
            logs += continue_result.logs
            found_errors = continue_result.found_errors or found_errors
            try_one_step = continue_result.try_one_step

            step_count = self.steps
            retry_on_blocked = RETRY_ON_BLOCKED
            while try_one_step and step_count > 0 and retry_on_blocked > 0:
                try_one_step = False
                logger.debug(f"step_count: {step_count} retry_on_blocked: {retry_on_blocked}")
                trx = self.make_combined_trx(step_count, 0)

                continue_result = self.send_and_confirm_continue([trx], none_receipts, retry_on_blocked, step_count)

                if continue_result.success_signature is not None:
                    return (continue_result.neon_res, continue_result.success_signature)
                none_receipts = continue_result.none_receipts
                logs += continue_result.logs
                found_errors = continue_result.found_errors or found_errors
                try_one_step = continue_result.try_one_step
                retry_on_blocked = continue_result.retry_on_blocked
                step_count = continue_result.step_count

            if step_count == 0:
                logs += ["Can't execute even one EVM instruction"]
                found_errors = True
            if retry_on_blocked == 0:
                logs += ["Stopped transaction because of blocked accounts"]
                found_errors = True

            if found_errors:
                if self.success_steps > 0:
                    break
                else:
                    raise Exception(str(logs))

        return self.call_cancel()


    def call_cancel(self):
        trx = self.instruction.make_cancel_transaction()

        logger.debug("Cancel")
        result = self.sender.send_measured_transaction(trx, self.eth_trx, 'CancelWithNonce')
        neon_res = NeonTxResultInfo()
        neon_res.slot = result['slot']
        return (neon_res, result['transaction']['signatures'][0])


    def send_and_confirm_continue(self, trxs: List[Transaction], none_receipts: List[str], retry_on_blocked: int = 1, step_count: int = 1) -> ContinueReturn:
        found_errors = False
        try_one_step = False
        logs = []
        success_signature = None
        success_neon_res = None

        receipts = self.sender.send_multiple_transactions_unconfirmed(trxs)
        receipts += none_receipts
        none_receipts = []
        result_list = self.sender.collect_results(receipts, eth_trx=self.eth_trx, reason=self.instruction_type)

        logger.debug(f"result_list: {len(result_list)} receipts: {len(receipts)}")
        for result, receipt in zip(result_list, receipts):
            if result is not None:
                if not check_error(result):
                    self.success_steps += 1
                    self.sender.get_measurements(result)
                    neon_res = NeonTxResultInfo(result)
                    if neon_res.is_valid():
                        success_signature = result['transaction']['signatures'][0]
                        success_neon_res = neon_res
                elif check_if_accounts_blocked(result):
                    logger.debug("Blocked account")
                    retry_on_blocked -= 1
                    time.sleep(0.5)
                    try_one_step = True
                elif check_if_program_exceeded_instructions(result):
                    logger.debug("Compute Limit")
                    step_count = int(step_count * 90 / 100)
                    try_one_step = True
                else:
                    logs += get_logs_from_reciept(result)
                    found_errors = True
            else:
                none_receipts.append(receipt)
        return self.ContinueReturn(success_signature, success_neon_res, none_receipts, logs, found_errors, try_one_step, retry_on_blocked, step_count)


    def steps_count(self):
        MAX_STEPS_IN_PACK = 16
        counted_steps = math.ceil(self.steps_emulated/self.steps) + self.addition_count()
        if self.success_steps >= counted_steps:
            return MAX_STEPS_IN_PACK
        elif (counted_steps - self.success_steps) <= MAX_STEPS_IN_PACK:
            return counted_steps - self.success_steps
        else:
            return MAX_STEPS_IN_PACK


    def addition_count(self):
        '''
        How many transactions are needed depending on trx type:
        CONTINUE_COMBINED: 2 (1 for begin and 1 for decreased steps)
        CONTINUE_HOLDER_COMB: 1 for begin
        0 otherwise
        '''
        addition_count = 0
        if self.instruction_type == self.CONTINUE_COMBINED:
            addition_count = 2
        elif self.instruction_type == self.CONTINUE_HOLDER_COMB:
            addition_count = 1
        return addition_count


    def make_combined_trx(self, steps, index):
        if self.instruction_type == self.CONTINUE_COMBINED:
            return self.instruction.make_partial_call_or_continue_transaction(steps - index)
        elif self.instruction_type == self.CONTINUE_HOLDER_COMB:
            return self.instruction.make_partial_call_or_continue_from_account_data(steps, index)
        else:
            raise Exception("Unknown continue type: {}".format(self.instruction_type))

