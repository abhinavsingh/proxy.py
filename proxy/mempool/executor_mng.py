import asyncio
import dataclasses
import socket
from abc import ABC, abstractmethod
from collections import deque
from typing import List, Tuple, Deque, Set, cast

from logged_groups import logged_group
from neon_py.network import PipePickableDataClient

from ..common_neon.config import IConfig

from .mempool_api import MPRequest, IMPExecutor, MPRequestType, MPTxRequest
from .mempool_executor import MPExecutor


class MPExecutorClient(PipePickableDataClient):

    def __init__(self, client_sock: socket.socket):
        PipePickableDataClient.__init__(self, client_sock=client_sock)


class IMPExecutorMngUser(ABC):

    @abstractmethod
    def on_resource_released(self, resource_id: int):
        assert False


@logged_group("neon.MemPool")
class MPExecutorMng(IMPExecutor):

    BRING_BACK_EXECUTOR_TIMEOUT_SEC = 1800

    @dataclasses.dataclass
    class ExecutorInfo:
        executor: MPExecutor
        client: MPExecutorClient
        id: int

    def __init__(self, user: IMPExecutorMngUser, executor_count: int, config: IConfig):
        self.info(f"Initialize executor mng with executor_count: {executor_count}")
        self._available_executor_pool: Deque[int] = deque()
        self._busy_executor_pool: Set[int] = set()
        self._executors: List[MPExecutorMng.ExecutorInfo] = list()
        self._user = user
        for i in range(executor_count):
            executor_info = MPExecutorMng._create_executor(i, config)
            self._executors.append(executor_info)
            self._available_executor_pool.appendleft(i)
            executor_info.executor.start()

    async def async_init(self):
        for ex_info in self._executors:
            await ex_info.client.async_init()

    def submit_mp_request(self, mp_request: MPRequest) -> Tuple[int, asyncio.Task]:
        executor_id, executor = self._get_executor()
        if mp_request.type == MPRequestType.SendTransaction:
            tx_hash = cast(MPTxRequest, mp_request).signature
            self.debug(f"Tx: {tx_hash} - scheduled on executor: {executor_id}")
        task = asyncio.get_event_loop().create_task(executor.send_data_async(mp_request))
        return executor_id, task

    def is_available(self) -> bool:
        return self._has_available()

    def _has_available(self) -> bool:
        return len(self._available_executor_pool) > 0

    def _get_executor(self) -> Tuple[int, MPExecutorClient]:
        executor_id = self._available_executor_pool.pop()
        self.debug(f"Acquire executor: {executor_id}")
        self._busy_executor_pool.add(executor_id)
        executor_info = self._executors[executor_id]
        return executor_id, executor_info.client

    def on_no_liquidity(self, resource_id: int):
        self.debug(f"No liquidity, executor: {resource_id} - will be unblocked in: {MPExecutorMng.BRING_BACK_EXECUTOR_TIMEOUT_SEC} sec")
        asyncio.get_event_loop().create_task(self._release_executor_later(resource_id))

    async def _release_executor_later(self, executor_id: int):
        await asyncio.sleep(MPExecutorMng.BRING_BACK_EXECUTOR_TIMEOUT_SEC)
        self.release_resource(executor_id)

    def release_resource(self, resource_id: int):
        self.debug(f"Release executor: {resource_id}")
        self._busy_executor_pool.remove(resource_id)
        self._available_executor_pool.appendleft(resource_id)
        self._user.on_resource_released(resource_id)

    @staticmethod
    def _create_executor(executor_id: int, config: IConfig) -> ExecutorInfo:
        client_sock, srv_sock = socket.socketpair()
        executor = MPExecutor(executor_id, srv_sock, config)
        client = MPExecutorClient(client_sock)
        return MPExecutorMng.ExecutorInfo(executor=executor, client=client, id=executor_id)

    def __del__(self):
        for executor_info in self._executors:
            executor_info.executor.kill()
        self._busy_executor_pool.clear()
        self._available_executor_pool.clear()
