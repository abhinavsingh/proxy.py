from __future__ import annotations

import asyncio
import logging
from random import randint

from web3 import Web3, Account
from typing import Tuple, Any, List, Dict

import unittest
from unittest.mock import patch, MagicMock, call

from ..mempool.mempool import MemPool, IMPExecutor
from ..mempool.mempool_api import MPRequest, MPTxRequest, MPTxResult, MPResultCode
from ..mempool.mempool_schedule import MPTxSchedule, MPSenderTxPool
from ..common_neon.eth_proto import Trx as NeonTx

from .testing_helpers import create_account


def get_transfer_mp_request(*, req_id: str, nonce: int, gas: int, gasPrice: int, from_acc: Account = None,
                            to_acc: Account = None, value: int = 0, data: bytes = b'') -> MPTxRequest:
    if from_acc is None:
        from_acc = create_account()

    if to_acc is None:
        to_acc = create_account()
    to_addr = to_acc.address
    w3 = Web3()
    signed_tx_data = w3.eth.account.sign_transaction(
        dict(nonce=nonce, chainId=111, gas=gas, gasPrice=gasPrice, to=to_addr, value=value, data=data),
        from_acc.key
    )
    signature = signed_tx_data.hash.hex()
    neon_tx = NeonTx.fromString(bytearray(signed_tx_data.rawTransaction))
    mp_tx_request = MPTxRequest(req_id=req_id, signature=signature, neon_tx=neon_tx)
    return mp_tx_request


class MockTask:

    def __init__(self, result: Any, is_done: bool = True, exception: Exception = None):
        self._result = result
        self._is_done = is_done
        self._exception = exception

    def done(self):
        return self._is_done

    def result(self):
        return self._result

    def exception(self):
        return self._exception


class MockMPExecutor(IMPExecutor):

    def submit_mp_request(self, mp_reqeust: MPRequest) -> Tuple[int, MockTask]:
        return 1, MockTask(MPTxResult(MPResultCode.Done, None))

    def is_available(self) -> bool:
        return False

    def on_no_liquidity(self, resource_id: int):
        pass

    def release_resource(self, resource_id: int):
        pass


class TestMemPool(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon.MemPool")
        neon_logger.setLevel(logging.ERROR)

    async def asyncSetUp(self):
        self._executor = MockMPExecutor()
        self._mempool = MemPool(self._executor, capacity=4096)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available", return_value=True)
    async def test_single_sender_single_tx(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request gets in effect"""
        mp_tx_request = get_transfer_mp_request(req_id="0000001", nonce=0, gasPrice=30000, gas=987654321, value=1, data=b'')
        await self._mempool.enqueue_mp_request(mp_tx_request)
        await asyncio.sleep(0)

        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(mp_tx_request)

    @patch.object(MockMPExecutor, "submit_mp_request", return_value=(1, MockTask(MPTxResult(MPResultCode.Done, None))))
    @patch.object(MockMPExecutor, "is_available", return_value=False)
    async def test_single_sender_couple_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_requests get in effect in the right order"""
        from_acc = create_account()
        to_acc = create_account()
        req_data = [dict(req_id="0000000", nonce=0, gasPrice=30000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc),
                    dict(req_id="0000001", nonce=1, gasPrice=29000, gas=987654321, value=1, from_acc=from_acc, to_acc=to_acc)]
        requests = await self._enqueue_requests(req_data)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_not_called()
        is_available_mock.return_value = True
        self._mempool.on_resource_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 10)

        submit_mp_request_mock.assert_has_calls([call(requests[0]), call(requests[1])])

    @patch.object(MockMPExecutor, "submit_mp_request", return_value=(1, MockTask(MPTxResult(MPResultCode.Done, None))))
    @patch.object(MockMPExecutor, "is_available", return_value=False)
    async def test_2_senders_4_txs(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request from different senders gets in effect in the right order"""
        acc = [create_account() for i in range(3)]
        req_data = [dict(req_id="000", nonce=0, gasPrice=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="001", nonce=1, gasPrice=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="002", nonce=0, gasPrice=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2])]
        requests = await self._enqueue_requests(req_data)
        is_available_mock.return_value = True
        self._mempool.on_resource_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC * 2)

        submit_mp_request_mock.assert_has_calls([call(requests[2]), call(requests[0]), call(requests[3]), call(requests[1])])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_mp_waits_for_previous_tx_done(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if an enqueued mp_tx_request waits for the previous one from the same sender"""
        submit_mp_request_mock.return_value = (1, MockTask(None, is_done=False))
        is_available_mock.return_value = False
        acc_0 = create_account()
        acc_1 = create_account()
        req_data = [dict(req_id="000", nonce=0, gasPrice=10000, gas=1000, value=1, from_acc=acc_0, to_acc=acc_1),
                    dict(req_id="001", nonce=1, gasPrice=10000, gas=1500, value=2, from_acc=acc_0, to_acc=acc_1)]
        requests = await self._enqueue_requests(req_data)
        is_available_mock.return_value = True
        for i in range(2):
            await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)
            self._mempool.on_resource_got_available(1)
        submit_mp_request_mock.assert_called_once_with(requests[0])

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_higher_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if the transaction with the same nonce but the higher gasPrice substitutes the current one"""
        from_acc = create_account()
        base_request = get_transfer_mp_request(req_id="0", from_acc=from_acc, nonce=0, gasPrice=30000, gas=987654321, value=1, data=b'')
        await self._mempool._schedule_mp_tx_request(base_request)
        subst_request = get_transfer_mp_request(req_id="1", from_acc=from_acc, nonce=0, gasPrice=40000, gas=987654321, value=2, data=b'')
        await self._mempool._schedule_mp_tx_request(subst_request)
        is_available_mock.return_value = True
        self._mempool.on_resource_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(subst_request)

    @patch.object(MockMPExecutor, "submit_mp_request")
    @patch.object(MockMPExecutor, "is_available")
    async def test_subst_with_lower_gas_price(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if the transaction with the same nonce but the lower gasPrice is ignored"""
        from_acc = create_account()
        base_request = get_transfer_mp_request(req_id="0", from_acc=from_acc, nonce=0, gasPrice=40000, gas=987654321, value=1, data=b'')
        await self._mempool._schedule_mp_tx_request(base_request)
        subst_request = get_transfer_mp_request(req_id="1", from_acc=from_acc, nonce=0, gasPrice=30000, gas=987654321, value=2, data=b'')
        await self._mempool._schedule_mp_tx_request(subst_request)
        is_available_mock.return_value = True
        self._mempool.on_resource_got_available(1)
        await asyncio.sleep(0)
        submit_mp_request_mock.assert_called_once()
        submit_mp_request_mock.assert_called_with(base_request)

    @patch.object(MockMPExecutor, "is_available")
    async def test_check_pending_tx_count(self, is_available_mock: MagicMock):
        """Checks if all incoming mp_tx_requests those are not processed are counted as pending"""
        acc = [create_account() for i in range(3)]
        req_data = [dict(req_id="000", nonce=0, gasPrice=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="001", nonce=1, gasPrice=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[2]),
                    dict(req_id="002", nonce=0, gasPrice=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="004", nonce=2, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2])]
        requests = await self._enqueue_requests(req_data)
        acc_0_count = self._mempool.get_pending_trx_count(requests[0].sender_address)
        self.assertEqual(acc_0_count, 2)
        acc_1_count = self._mempool.get_pending_trx_count(requests[3].sender_address)
        self.assertEqual(acc_1_count, 3)
        is_available_mock.return_value = True
        self._mempool.on_resource_got_available(1)
        await asyncio.sleep(MemPool.CHECK_TASK_TIMEOUT_SEC)
        acc_1_count = self._mempool.get_pending_trx_count(requests[3].sender_address)
        self.assertEqual(acc_1_count, 2)

    @patch.object(MockMPExecutor, "submit_mp_request", return_value=(1, MockTask(MPTxResult(MPResultCode.Done, None))))
    @patch.object(MockMPExecutor, "is_available")
    async def test_over_9000_transfers(self, is_available_mock: MagicMock, submit_mp_request_mock: MagicMock):
        """Checks if all mp_tx_requests are processed by the MemPool"""
        acc_count_max = 1_000
        from_acc_count = 10
        sleep_sec = 2
        nonce_count = 100
        req_count = from_acc_count * nonce_count
        acc = [create_account() for i in range(acc_count_max)]
        for acc_i in range(0, from_acc_count):
            nonces = [i for i in range(0, nonce_count)]
            while len(nonces) > 0:
                index = randint(0, len(nonces) - 1)
                nonce = nonces.pop(index)
                request = get_transfer_mp_request(from_acc=acc[acc_i], to_acc=acc[randint(0, acc_count_max-1)],
                                                  req_id=str(acc_i) + " " + str(nonce), nonce=nonce,
                                                  gasPrice=randint(50000, 100000), gas=randint(4000, 10000))
                await self._mempool.enqueue_mp_request(request)
        is_available_mock.return_value = True
        self._mempool.on_resource_got_available(1)
        await asyncio.sleep(sleep_sec)
        for ac in acc[:from_acc_count]:
            acc_nonce = 0
            for call in submit_mp_request_mock.call_args_list:
                request = call.args[0]
                if ac.address.lower() == request.sender_address:
                    self.assertEqual(request.nonce, acc_nonce)
                    acc_nonce += 1

        self.assertEqual(submit_mp_request_mock.call_count, req_count)

    async def _enqueue_requests(self, req_data: List[Dict[str, Any]]) -> List[MPTxRequest]:
        requests = [get_transfer_mp_request(**req) for req in req_data]
        for req in requests:
            await self._mempool.enqueue_mp_request(req)
        return requests


class TestMPSchedule(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon.MemPool")
        neon_logger.setLevel(logging.ERROR)

    def test_capacity_oversized_simple(self):
        """Checks if mp_schedule doesn't get oversized in simple way"""
        mp_schedule_capacity = 3
        schedule = MPTxSchedule(mp_schedule_capacity)
        acc = [create_account() for i in range(3)]
        req_data = [dict(req_id="000", nonce=0, gasPrice=60000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="001", nonce=1, gasPrice=60000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="002", nonce=1, gasPrice=40000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="003", nonce=1, gasPrice=70000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1]),
                    dict(req_id="004", nonce=2, gasPrice=25000, gas=1000, value=1, from_acc=acc[1], to_acc=acc[2]),
                    dict(req_id="005", nonce=2, gasPrice=50000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1]),
                    dict(req_id="006", nonce=3, gasPrice=50000, gas=1000, value=1, from_acc=acc[2], to_acc=acc[1])
                    ]
        self.requests = [get_transfer_mp_request(**req) for req in req_data]
        for request in self.requests[0:3]:
            schedule.add_mp_tx_request(request)

        self.assertIs(schedule.acquire_tx_for_execution(), self.requests[0])
        self.assertIs(schedule.acquire_tx_for_execution(), self.requests[2])
        self.assertIs(schedule.acquire_tx_for_execution(), None)
        for request in self.requests[3:]:
            schedule.add_mp_tx_request(request)
        self.assertEqual(acc[2].address.lower(), schedule._sender_tx_pools[0].sender_address)
        self.assertEqual(acc[0].address.lower(), schedule._sender_tx_pools[1].sender_address)
        self.assertEqual(acc[1].address.lower(), schedule._sender_tx_pools[2].sender_address)
        self.assertEqual(acc[1].address.lower(), schedule._sender_tx_pools[2].sender_address)
        self.assertIs(self.requests[3], schedule._sender_tx_pools[0]._txs[0])
        self.assertIs(self.requests[0], schedule._sender_tx_pools[1]._txs[0])
        self.assertIs(self.requests[2], schedule._sender_tx_pools[2]._txs[0])

        self.assertEqual(3, schedule.get_mp_tx_count())
        self.assertEqual(3, len(schedule._sender_tx_pools))
        self.assertEqual(1, schedule.get_pending_trx_count(acc[0].address.lower()))
        self.assertEqual(1, schedule.get_pending_trx_count(acc[1].address.lower()))
        self.assertEqual(1, schedule.get_pending_trx_count(acc[2].address.lower()))
        self.assertEqual(3, len(schedule._sender_tx_pools))
        self.assertIs(self.requests[3], schedule._sender_tx_pools[0]._txs[0])

    def test_capacity_oversized(self):
        """Checks if mp_schedule doesn't get oversized with a quite big set of mp_tx_requests"""

        acc_count_max = 10
        from_acc_count = 5
        nonce_count = 1000
        mp_schedule_capacity = 4000
        schedule = MPTxSchedule(mp_schedule_capacity)
        acc = [create_account() for i in range(acc_count_max)]
        for acc_i in range(0, from_acc_count):
            nonces = [i for i in range(0, nonce_count)]
            while len(nonces) > 0:
                index = randint(0, len(nonces) - 1)
                nonce = nonces.pop(index)
                request = get_transfer_mp_request(from_acc=acc[acc_i], to_acc=acc[randint(0, acc_count_max-1)],
                                                  req_id=str(acc_i) + " " + str(nonce), nonce=nonce_count - nonce - 1,
                                                  gasPrice=randint(50000, 100000), gas=randint(4000, 10000))
                schedule.add_mp_tx_request(request)
        self.assertEqual(mp_schedule_capacity, schedule.get_mp_tx_count())


class TestMPSenderTxPool(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.turn_logger_off()

    @classmethod
    def turn_logger_off(cls) -> None:
        neon_logger = logging.getLogger("neon.MemPool")
        neon_logger.setLevel(logging.ERROR)

    def setUp(self) -> None:
        self._pool = MPSenderTxPool()
        acc = [create_account() for i in range(2)]
        req_data = [dict(req_id="000", nonce=3, gasPrice=30000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="001", nonce=1, gasPrice=21000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="002", nonce=0, gasPrice=40000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="003", nonce=2, gasPrice=25000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1]),
                    dict(req_id="004", nonce=4, gasPrice=25000, gas=1000, value=1, from_acc=acc[0], to_acc=acc[1])]
        self._requests = [get_transfer_mp_request(**req) for req in req_data]
        for request in self._requests:
            self._pool.add_tx(request)

    def test_drop_last_request(self):
        """Checks if transaction pool drops the request with highest nonce properly"""
        self._pool.drop_last_request()
        self.assertEqual(self._pool.len(), 4)
        self.assertEqual(self._pool.get_tx(), self._requests[2])
        self.assertEqual(self._pool._txs[-1], self._requests[0])

    def test_drop_last_request_if_processing(self):
        """Checks if transaction pool doesn't drop the reqeust with the highest nonce if it's in process"""
        tx = self._pool.acquire_tx()
        self.assertIs(tx, self._requests[2])
        with self.assertLogs("neon.MemPool", logging.DEBUG) as logs:
            for i in range(0, 5):
                self._pool.drop_last_request()
            self.assertEqual(5, len(logs.records))
            self.assertEqual(f"Skip removing transaction: {tx.log_str} - processing", logs.records[4].msg)
            self.assertEqual(1, self._pool.len())

    def test_drop_request_away(self):
       tx = self._pool.acquire_tx()
       self.assertTrue(self._pool.is_processing())
       self._pool.drop_request_away(tx)
       self.assertEqual(self._pool.len(), 0)
