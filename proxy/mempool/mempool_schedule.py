import bisect
from typing import List, Dict, Optional, Tuple

from logged_groups import logged_group

from ..common_neon.eth_proto import Trx as NeonTx

from .mempool_api import MPTxRequest, MPSendTxResult


@logged_group("neon.MemPool")
class MPTxDict:
    def __init__(self) -> None:
        self._tx_hash_dict: Dict[str, MPTxRequest] = {}

    def add(self, tx: MPTxRequest) -> bool:
        if tx.signature in self._tx_hash_dict:
            self.error(f'Tx: {tx.signature} with {tx.log_str} is already in the dictionary')
            return False

        self._tx_hash_dict[tx.signature] = tx
        return True

    def pop(self, tx: MPTxRequest) -> bool:
        popped_tx = self._tx_hash_dict.pop(tx.signature, None)
        if popped_tx is None:
            self.error(f'Tx: {tx.signature} with {tx.log_str} does not exist in the dictionary')
        return popped_tx is not None

    def get(self, tx_hash: str) -> Optional[MPTxRequest]:
        return self._tx_hash_dict.get(tx_hash, None)


@logged_group("neon.MemPool")
class MPSenderTxPool:
    def __init__(self, sender_address: Optional[str] = None, tx_dict: Optional[MPTxDict] = None):
        self.sender_address = sender_address
        self._tx_dict = tx_dict
        self._tx_list: List[MPTxRequest] = []
        self._processing_tx: Optional[MPTxRequest] = None

    def __eq__(self, other):
        return self.first_tx_gas_price() == other.first_tx_gas_price()

    def __lt__(self, other):
        return self.first_tx_gas_price() > other.first_tx_gas_price()

    def _on_add_tx(self, tx: MPTxRequest):
        if self._tx_dict is None:
            return
        self._tx_dict.add(tx)

    def _on_pop_tx(self, tx: MPTxRequest):
        if self._tx_dict is None:
            return
        self._tx_dict.pop(tx)

    def add_tx(self, mp_tx_request: MPTxRequest) -> MPSendTxResult:
        index = bisect.bisect_left(self._tx_list, mp_tx_request)
        last_nonce = self.last_nonce()
        if self._processing_tx is not None and mp_tx_request.nonce == self._processing_tx.nonce:
            tx = self._processing_tx
            self.warning(f"Failed to replace processing tx: {tx.log_str} with: {mp_tx_request.log_str}")
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        found_tx: Optional[MPTxRequest] = self._tx_list[index] if index < len(self._tx_list) else None
        if found_tx is not None and found_tx.nonce == mp_tx_request.nonce:
            self.debug(f"Nonce are equal: {found_tx.nonce}, found: {found_tx.log_str}, new: {mp_tx_request.log_str}")
            if found_tx.gas_price < mp_tx_request.gas_price:
                self._on_pop_tx(found_tx)
                self._tx_list[index] = mp_tx_request
                self._on_add_tx(mp_tx_request)
                return MPSendTxResult(success=True, last_nonce=last_nonce)
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        if (last_nonce is not None) and (mp_tx_request.nonce != last_nonce + 1):
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        if (last_nonce is None) and (mp_tx_request.nonce != mp_tx_request.sender_tx_cnt):
            return MPSendTxResult(success=False, last_nonce=last_nonce)

        self._tx_list.insert(index, mp_tx_request)
        self._on_add_tx(mp_tx_request)
        self.debug(f"New mp_tx_request: {mp_tx_request.log_str} - inserted at: {index}")
        return MPSendTxResult(success=True, last_nonce=last_nonce)

    def get_tx(self):
        return None if self.is_empty() else self._tx_list[0]

    def acquire_tx(self):
        if self.is_processing():
            return None
        self._processing_tx = self.get_tx()
        return self._processing_tx

    def len(self) -> int:
        return len(self._tx_list)

    def last_nonce(self) -> Optional[int]:
        if self.len() == 0:
            return None
        return self._tx_list[-1].nonce

    def first_tx_gas_price(self):
        tx = self.get_tx()
        return tx.gas_price if tx is not None else 0

    def _validate_processing_tx(self, action: str, nonce: int) -> bool:
        if self._processing_tx is None:
            self.error(f"Failed to {action} tx with nonce: {nonce}, processing tx is None")
            return False
        if self._processing_tx.nonce != nonce:
            self.error(
                f"Failed to {action} tx, " +
                f"processing tx has different nonce: {self._processing_tx.nonce} than: {nonce}"
            )
            return False

        if self.is_empty():
            self.error(f"Failed to {action} tx, sender {self.sender_address} doesn't have transactions")
            return False
        tx = self._tx_list[0]
        if tx is not self._processing_tx:
            self.error(
                f"Failed to {action} tx, " +
                f"processing tx has another signature: {self._processing_tx.signature} than: {tx.signature}"
            )
            return False

        return True

    def done_tx(self, nonce: int):
        if not self._validate_processing_tx('finish', nonce):
            return

        self._tx_list = self._tx_list[1:]
        self._on_pop_tx(self._processing_tx)
        self.debug(f"On tx done: {self._processing_tx.log_str} - removed. The: {self.len()} txs are left")
        self._processing_tx = None

    def is_empty(self) -> bool:
        return self.len() == 0

    def is_processing(self) -> bool:
        return self._processing_tx is not None

    def drop_last_request(self) -> bool:
        if self.is_empty():
            self.error("Failed to drop last request from empty sender tx pool")
            return False
        tx = self._tx_list[-1]
        if self._processing_tx is tx:
            self.debug(f"Skip removing transaction: {self._processing_tx.log_str} - processing")
            return False

        self.debug(f"Remove last mp_tx_request from sender: {self.sender_address} - {tx.log_str}")
        self._tx_list.pop()
        self._on_pop_tx(tx)
        return True

    def fail_tx(self, nonce: int):
        self.debug(f"Remove mp_tx_request: {self.sender_address}:{nonce}")
        if not self._validate_processing_tx('drop', nonce):
            return

        for tx in self._tx_list:
            self.debug(f"Removed mp_tx_request from sender: {self.sender_address} - {tx.log_str}")
            self._on_pop_tx(tx)

        self._tx_list.clear()
        self._processing_tx = None

    def reschedule_tx(self, nonce):
        self.debug(f"Reschedule mp_tx_request: {self.sender_address}:{nonce}")
        if not self._validate_processing_tx('reschedule', nonce):
            return

        self.debug(f"Reset processing tx back to pending: {self.sender_address} - {self._processing_tx.log_str}")
        self._processing_tx = None


@logged_group("neon.MemPool")
class MPTxSchedule:
    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._sender_tx_pools: List[MPSenderTxPool] = []
        self._tx_dict = MPTxDict()

    def _pop_sender_txs(self, sender_address: str) -> Optional[MPSenderTxPool]:
        for i, sender_tx_pool in enumerate(self._sender_tx_pools):
            if sender_tx_pool.sender_address != sender_address:
                continue
            return self._sender_tx_pools.pop(i)
        return None

    def _get_sender_txs(self, sender_address: str) -> Tuple[Optional[MPSenderTxPool], int]:
        for i, sender in enumerate(self._sender_tx_pools):
            if sender.sender_address != sender_address:
                continue
            return sender, i
        return None, -1

    def add_mp_tx_request(self, mp_tx_request: MPTxRequest) -> MPSendTxResult:
        self.debug(f"Add mp_tx_request: {mp_tx_request.log_str}")
        sender_txs = self._pop_sender_or_create(mp_tx_request.sender_address)
        self.debug(f"Got collection for sender: {mp_tx_request.sender_address}, there are already txs: {sender_txs.len()}")
        result: MPSendTxResult = sender_txs.add_tx(mp_tx_request)
        bisect.insort_left(self._sender_tx_pools, sender_txs)

        self._check_oversized_and_reduce()
        return result

    def get_mp_tx_count(self):
        count = 0
        for sender_txs in self._sender_tx_pools:
            count += sender_txs.len()
        return count

    def _check_oversized_and_reduce(self):
        count = self.get_mp_tx_count()
        tx_to_remove = count - self._capacity
        sender_to_remove = []
        for sender in self._sender_tx_pools[::-1]:
            if tx_to_remove <= 0:
                break
            if not sender.drop_last_request():
                continue
            if sender.is_empty():
                sender_to_remove.append(sender)
            tx_to_remove -= 1
        for sender in sender_to_remove:
            self._sender_tx_pools.remove(sender)

    def _pop_sender_or_create(self, sender_address: str) -> MPSenderTxPool:
        sender = self._pop_sender_txs(sender_address)
        return MPSenderTxPool(sender_address, self._tx_dict) if sender is None else sender

    def acquire_tx_for_execution(self) -> Optional[MPTxRequest]:

        if len(self._sender_tx_pools) == 0:
            return None

        tx: Optional[MPTxRequest] = None
        for sender_txs in self._sender_tx_pools:
            if sender_txs.is_processing():
                continue
            tx = sender_txs.acquire_tx()
            break

        return tx

    def on_request_done(self, sender_addr: str, nonce: int):
        sender = self._pop_sender_txs(sender_addr)
        if sender is None:
            self.error(f"Failed to process tx done, address: {sender_addr}, nonce: {nonce} - sender not found")
            return
        sender.done_tx(nonce)
        if not sender.is_empty():
            bisect.insort_left(self._sender_tx_pools, sender)

    def get_pending_tx_count(self, sender_addr: str) -> int:
        sender, _ = self._get_sender_txs(sender_addr)
        return 0 if sender is None else sender.len()

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        sender, _ = self._get_sender_txs(sender_addr)
        return None if sender is None else sender.last_nonce()

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        tx = self._tx_dict.get(tx_hash)
        if tx is not None:
            return tx.neon_tx
        return None

    def fail_tx(self, sender_addr: str, nonce: int) -> bool:
        sender, i = self._get_sender_txs(sender_addr)
        if sender is None:
            self.error(f"Failed drop request, no sender by sender_address: {sender_addr}")
            return False
        sender.fail_tx(nonce)
        if sender.len() == 0:
            self._sender_tx_pools.pop(i)
        return True

    def reschedule_tx(self, sender_address: str, nonce: int):
        sender, _ = self._get_sender_txs(sender_address)
        if sender is None:
            self.error(f"Failed reschedule, no sender by sender_address: {sender_address}")
            return
        sender.reschedule_tx(nonce)
