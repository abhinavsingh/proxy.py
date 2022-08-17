import asyncio
from typing import List, Tuple, Optional, cast

from logged_groups import logged_group
from neon_py.data import Result

from ..common_neon.eth_proto import Trx as NeonTx

from .mempool_api import MPRequest, MPResultCode, MPTxResult, IMPExecutor, MPRequestType, MPTxRequest, \
                         MPPendingTxNonceReq, MPPendingTxByHashReq, MPSendTxResult
from .mempool_schedule import MPTxSchedule


@logged_group("neon.MemPool")
class MemPool:

    CHECK_TASK_TIMEOUT_SEC = 0.01
    RESCHEDULE_TIMEOUT_SEC = 0.4

    def __init__(self, executor: IMPExecutor, capacity: int):
        self.info(f"Init mempool schedule with capacity: {capacity}")
        self._tx_schedule = MPTxSchedule(capacity)
        self._schedule_cond = asyncio.Condition()
        self._processing_tasks: List[Tuple[int, asyncio.Task, MPRequest]] = []
        self._process_tx_results_task = asyncio.get_event_loop().create_task(self.check_processing_tasks())
        self._process_schedule_task = asyncio.get_event_loop().create_task(self.process_tx_schedule())
        self._is_active: bool = True
        self._executor = executor

    async def enqueue_mp_request(self, mp_request: MPRequest):
        if mp_request.type == MPRequestType.SendTransaction:
            tx_request = cast(MPTxRequest, mp_request)
            return await self.schedule_mp_tx_request(tx_request)
        elif mp_request.type == MPRequestType.GetLastTxNonce:
            pending_nonce_req = cast(MPPendingTxNonceReq, mp_request)
            return self.get_pending_tx_nonce(pending_nonce_req.sender)
        elif mp_request.type == MPRequestType.GetTxByHash:
            pending_tx_by_hash_req = cast(MPPendingTxByHashReq, mp_request)
            return self.get_pending_tx_by_hash(pending_tx_by_hash_req.tx_hash)

    async def schedule_mp_tx_request(self, mp_request: MPTxRequest) -> MPSendTxResult:
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        try:
            result: MPSendTxResult = self._tx_schedule.add_mp_tx_request(mp_request)
            count = self.get_pending_tx_count(mp_request.sender_address)
            self.debug(f"Got and scheduled mp_tx_request: {mp_request.log_str}, pending in pool: {count}", extra=log_ctx)
            return result
        except Exception as err:
            self.error(f"Failed to schedule mp_tx_request: {mp_request.log_str}. Error: {err}", extra=log_ctx)
        finally:
            await self._kick_tx_schedule()

    def get_pending_tx_count(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_count(sender_addr)

    def get_pending_tx_nonce(self, sender_addr: str) -> int:
        return self._tx_schedule.get_pending_tx_nonce(sender_addr)

    def get_pending_tx_by_hash(self, tx_hash: str) -> Optional[NeonTx]:
        return self._tx_schedule.get_pending_tx_by_hash(tx_hash)

    async def process_tx_schedule(self):
        while True:
            async with self._schedule_cond:
                await self._schedule_cond.wait()
                await self._schedule_cond.wait_for(self.is_active)
                self.debug(f"Schedule processing  got awake, condition: {self._schedule_cond.__repr__()}")
                while self._executor.is_available():
                    mp_request: MPTxRequest = self._tx_schedule.acquire_tx_for_execution()
                    if mp_request is None:
                        break

                    try:
                        log_ctx = {"context": {"req_id": mp_request.req_id}}
                        self.debug(f"Got mp_tx_request from schedule: {mp_request.log_str}, left senders in schedule: {len(self._tx_schedule._sender_tx_pools)}", extra=log_ctx)
                        self.submit_request_to_executor(mp_request)
                    except Exception as err:
                        self.error(f"Failed enqueue to execute mp_tx_request: {mp_request.log_str}. Error: {err}")

    def submit_request_to_executor(self, mp_tx_request: MPRequest):
        resource_id, task = self._executor.submit_mp_request(mp_tx_request)
        self._processing_tasks.append((resource_id, task, mp_tx_request))

    async def check_processing_tasks(self):
        while True:
            has_processed_result = False
            not_finished_tasks = []
            for resource_id, task, mp_request in self._processing_tasks:
                if not task.done():
                    not_finished_tasks.append((resource_id, task, mp_request))
                    continue
                has_processed_result = True
                exception = task.exception()
                if exception is not None:
                    log_ctx = {"context": {"req_id": mp_request.req_id}}
                    self.error(f"Exception during processing request: {exception} - tx will be dropped away", extra=log_ctx)
                    self._on_fail_tx(mp_request)
                    self._executor.release_resource(resource_id)
                    continue

                mp_tx_result: MPTxResult = task.result()
                assert isinstance(mp_tx_result, MPTxResult), f"Got unexpected result: {mp_tx_result}"
                self._process_mp_result(resource_id, mp_tx_result, mp_request)

            self._processing_tasks = not_finished_tasks
            if has_processed_result:
                await self._kick_tx_schedule()
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)

    def _process_mp_result(self, resource_id: int, mp_tx_result: MPTxResult, mp_request: MPTxRequest):
        log_ctx = {"context": {"req_id": mp_request.req_id}}
        try:
            log_fn = self.warning if mp_tx_result.code != MPResultCode.Done else self.debug
            log_fn(f"On mp tx result:  {mp_tx_result} - of: {mp_request.log_str}", extra=log_ctx)

            if mp_tx_result.code == MPResultCode.BlockedAccount:
                self._on_blocked_accounts_result(mp_request, mp_tx_result)
            elif mp_tx_result.code == MPResultCode.Unspecified:
                self._on_fail_tx(mp_request)
            elif mp_tx_result.code == MPResultCode.Done:
                self._on_request_done(mp_request)

        except Exception as err:
            self.error(f"Exception during the result processing: {err}", extra=log_ctx)
        finally:
            self._executor.release_resource(resource_id)

    def _on_blocked_accounts_result(self, mp_tx_request: MPTxRequest, mp_tx_result: MPTxResult):
        self.debug(f"For tx: {mp_tx_request.log_str} - got blocked account transaction status: {mp_tx_result.data}. "
                   f"Will be rescheduled in: {self.RESCHEDULE_TIMEOUT_SEC} sec.")
        asyncio.get_event_loop().create_task(self._reschedule_tx(mp_tx_request))

    async def _reschedule_tx(self, tx_request: MPTxRequest):
        await asyncio.sleep(self.RESCHEDULE_TIMEOUT_SEC)
        self._tx_schedule.reschedule_tx(tx_request.sender_address, tx_request.nonce)
        await self._kick_tx_schedule()

    def _on_request_done(self, tx_request: MPTxRequest):
        sender = tx_request.sender_address
        self._tx_schedule.on_request_done(sender, tx_request.nonce)

        count = self.get_pending_tx_count(sender)
        log_ctx = {"context": {"req_id": tx_request.req_id}}
        self.debug(f"Reqeust done, pending tx count: {count}", extra=log_ctx)

    def _on_fail_tx(self, tx_request: MPTxRequest):
        sender = tx_request.sender_address
        if not self._tx_schedule.fail_tx(sender, tx_request.nonce):
            return
        count = self.get_pending_tx_count(tx_request.sender_address)
        log_ctx = {"context": {"req_id": tx_request.req_id}}
        self.debug(f"Reqeust: {tx_request.log_str} - dropped away, pending tx count: {count}", extra=log_ctx)

    async def _kick_tx_schedule(self):
        async with self._schedule_cond:
            # self.debug(f"Kick the schedule, condition: {self._schedule_cond.__repr__()}")
            self._schedule_cond.notify()

    def on_resource_got_available(self, resource_id: int):
        asyncio.get_event_loop().create_task(self._kick_tx_schedule())

    def suspend_processing(self) -> Result:
        if not self._is_active:
            self.warning("No need to suspend mempool, already suspended")
            return Result()
        self._is_active = False
        self.info("Transaction processing suspended")
        return Result()

    def resume_processing(self) -> Result:
        if self._is_active:
            self.warning("No need to resume mempool, not suspended")
            return Result()
        self._is_active = True
        self.info("Transaction processing resumed")
        return Result()

    def is_active(self) -> bool:
        return self._is_active
