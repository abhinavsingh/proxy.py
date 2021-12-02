import json
import logging
import os
import rlp
import time

from base58 import b58encode
from sha3 import keccak_256
from solana.publickey import PublicKey
from solana.rpc.api import SendTransactionError
from solana.sysvar import *
from solana.transaction import AccountMeta, Transaction

from ..core.acceptor.pool import new_acc_id_glob, acc_list_glob

from .address import accountWithSeed, AccountInfo, getTokenAddr
from .constants import STORAGE_SIZE, EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG, ACCOUNT_SEED_VERSION
from .emulator_interactor import call_emulated
from .layouts import ACCOUNT_INFO_LAYOUT
from .neon_instruction import NeonInstruction
from .solana_interactor import SolanaInteractor, check_if_continue_returned, check_if_program_exceeded_instructions
from ..environment import EVM_LOADER_ID
from ..plugin.eth_proto import Trx as EthTrx


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
                    return iterative_executor.call_signed_iterative()
                except Exception as err:
                    logger.debug(str(err))
                    if str(err).startswith("transaction too large:"):
                        logger.debug("Transaction too large, call call_signed_with_holder_acc():")
                        call_from_holder = True
                    else:
                        raise

            if call_from_holder:
                return iterative_executor.call_signed_with_holder_acc()
        finally:
            self.free_perm_accs()


    def create_instruction_constructor(self):
        return NeonInstruction(self.sender.get_operator_key(), self.eth_trx, self.eth_accounts, self.caller_token)


    def create_noniterative_executor(self):
        self.instruction.init_eth_trx(self.eth_trx, self.eth_accounts, self.caller_token)
        return NoniterativeTransactionSender(self.sender, self.instruction, self.create_acc_trx, self.eth_trx)


    def create_iterative_executor(self):
        self.instruction.init_iterative(self.storage, self.holder, self.perm_accs_id)
        return IterativeTransactionSender(self.sender, self.instruction, self.create_acc_trx, self.eth_trx, self.steps)


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
            minimum_balance = self.sender.get_rent_exempt_balance_for_size(storage_size)
            logger.debug("Minimum balance required for account {}".format(minimum_balance))

            trx = Transaction()
            trx.add(self.instruction.create_account_with_seed_trx(account, seed, minimum_balance, storage_size))
            self.sender.send_transaction(trx, eth_trx=self.eth_trx, reason='createAccountWithSeed')

        return account


    def create_multiple_accounts_with_seed(self, seeds, sizes):
        accounts = []
        trx = Transaction()

        for seed, storage_size in zip(seeds, sizes):
            account = accountWithSeed(self.sender.get_operator_key(), seed)
            accounts.append(account)

            minimum_balance = self.sender.get_rent_exempt_balance_for_size(storage_size)

            account_info = self.sender.get_account_info(account)
            if account_info is None:
                logger.debug("Minimum balance required for account {}".format(minimum_balance))

                trx.add(self.instruction.create_account_with_seed_trx(account, seed, minimum_balance, storage_size))
            else:
                (tag, lamports, owner) = account_info
                if lamports < minimum_balance:
                    raise Exception("insufficient balance")
                if PublicKey(owner) != PublicKey(EVM_LOADER_ID):
                    raise Exception("wrong owner")
                if tag not in {EMPTY_STORAGE_TAG, FINALIZED_STORAGE_TAG}:
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
                    code_account_balance = self.sender.get_rent_exempt_balance_for_size(code_size)
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

            elif address == sender_ether:
                sender_sol = PublicKey(acc_desc["account"])
            else:
                add_keys_05.append(AccountMeta(pubkey=acc_desc["account"], is_signer=False, is_writable=True))
                token_account = getTokenAddr(PublicKey(acc_desc["account"]))
                add_keys_05.append(AccountMeta(pubkey=token_account, is_signer=False, is_writable=True))
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
                AccountMeta(pubkey=getTokenAddr(contract_sol), is_signer=False, is_writable=True),
            ] + ([AccountMeta(pubkey=code_sol, is_signer=False, is_writable=code_writable)] if code_sol != None else []) + [
                AccountMeta(pubkey=sender_sol, is_signer=False, is_writable=True),
                AccountMeta(pubkey=self.caller_token, is_signer=False, is_writable=True),
            ] + add_keys_05


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
        result = self.sender.send_measured_transaction(call_txs_05, self.eth_trx, 'CallFromRawEthereumTX')
        return result['result']['transaction']['signatures'][0]


class IterativeTransactionSender:
    def __init__(self, solana_interactor: SolanaInteractor, neon_instruction: NeonInstruction, create_acc_trx: Transaction, eth_trx: EthTrx, steps: int):
        self.sender = solana_interactor
        self.instruction = neon_instruction
        self.create_acc_trx = create_acc_trx
        self.eth_trx = eth_trx
        self.steps = steps


    def call_signed_iterative(self):
        if len(self.create_acc_trx.instructions):
            precall_txs = Transaction()
            precall_txs.add(self.create_acc_trx)
            self.sender.send_measured_transaction(precall_txs, self.eth_trx, 'CreateAccountsForTrx')

        call_txs = self.instruction.make_iterative_call_transaction()

        logger.debug("Partial call")
        self.sender.send_measured_transaction(call_txs, self.eth_trx, 'PartialCallFromRawEthereumTXv02')

        return self.call_continue()


    def call_signed_with_holder_acc(self):
        self.write_trx_to_holder_account()
        if len(self.create_acc_trx.instructions):
            precall_txs = Transaction()
            precall_txs.add(self.create_acc_trx)
            self.sender.send_measured_transaction(precall_txs, self.eth_trx, 'create_accounts_for_deploy')

        # ExecuteTrxFromAccountDataIterative
        logger.debug("ExecuteTrxFromAccountDataIterative:")
        call_txs = self.instruction.make_call_from_account_instruction()
        self.sender.send_measured_transaction(call_txs, self.eth_trx, 'ExecuteTrxFromAccountDataIterativeV02')

        return self.call_continue()


    def write_trx_to_holder_account(self):
        msg = self.eth_trx.signature() + len(self.eth_trx.unsigned_msg()).to_bytes(8, byteorder="little") + self.eth_trx.unsigned_msg()

        # Write transaction to transaction holder account
        offset = 0
        receipts = []
        rest = msg
        while len(rest):
            (part, rest) = (rest[:1000], rest[1000:])
            # logger.debug("sender_sol %s %s %s", sender_sol, holder, acc.public_key())
            trx = self.instruction.make_write_transaction(offset, part)
            receipts.append(self.sender.send_transaction_unconfirmed(trx))
            offset += len(part)

        logger.debug("receipts %s", receipts)
        self.sender.collect_results(receipts, eth_trx=self.eth_trx, reason='WriteHolder')


    def call_continue(self):
        try:
            return self.call_continue_step_by_step()
        except Exception as err:
            logger.error("call_continue_step_by_step exception:")
            logger.debug(str(err))

        return self.call_cancel()


    def call_continue_step_by_step(self):
        while True:
            logger.debug("Continue iterative step:")
            result = self.call_continue_step()
            signature = check_if_continue_returned(result)
            if signature is not None:
                return signature


    def call_continue_step(self):
        step_count = self.steps
        while step_count > 0:
            trx = self.instruction.make_continue_instruction(step_count)

            logger.debug("Step count {}".format(step_count))
            try:
                result = self.sender.send_measured_transaction(trx, self.eth_trx, 'ContinueV02')
                return result
            except SendTransactionError as err:
                if check_if_program_exceeded_instructions(err.result):
                    step_count = int(step_count * 90 / 100)
                else:
                    raise
        raise Exception("Can't execute even one EVM instruction")


    def call_cancel(self):
        trx = self.instruction.make_cancel_instruction()

        logger.debug("Cancel")
        result = self.sender.send_measured_transaction(trx, self.eth_trx, 'CancelWithNonce')
        return result['result']['transaction']['signatures'][0]
