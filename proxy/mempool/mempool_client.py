from __future__ import annotations
import threading
from typing import Callable
from logged_groups import logged_group

from .mempool_api import MPTxRequest, MPPendingTxNonceReq, MPPendingTxByHashReq, MPSendTxResult

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg
from ..common_neon.utils import AddrPickableDataClient


def _guard_conn(method: Callable) -> Callable:
    def wrapper(self, *args, **kwargs):
        with self._mp_conn_lock:
            return method(self, *args, **kwargs)

    return wrapper


def _reconnecting(method: Callable) -> Callable:
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except (InterruptedError, Exception) as err:
            self.error(f"Failed to transfer data, unexpected err: {err}")
            self._reconnect_mp()
            raise
    return wrapper


@logged_group("neon.Proxy")
class MemPoolClient:

    RECONNECT_MP_TIME_SEC = 5

    def __init__(self, host: str, port: int):
        self.debug("Init MemPoolClient")
        self._mp_conn_lock = threading.Lock()
        self._address = (host, port)
        self._is_connecting = threading.Event()
        self._connect_mp()

    def _reconnect_mp(self):
        if self._is_connecting.is_set():
            return
        self._is_connecting.set()
        self.debug(f"Reconnecting MemPool in: {MemPoolClient.RECONNECT_MP_TIME_SEC} sec.")
        threading.Timer(MemPoolClient.RECONNECT_MP_TIME_SEC, self._connect_mp).start()

    @_guard_conn
    def _connect_mp(self):
        try:
            self.debug(f"Connect MemPool: {self._address}")
            self._pickable_data_client = AddrPickableDataClient(self._address)
        except Exception as err:
            self.error(f"Failed to connect MemPool: {self._address}, error: {err}")
            self._is_connecting.clear()
            self._reconnect_mp()
        finally:
            self._is_connecting.clear()

    @_guard_conn
    @_reconnecting
    def send_raw_transaction(self, req_id: str, signature: str, neon_tx: NeonTx, sender_tx_cnt: int,
                             neon_tx_exec_cfg: NeonTxExecCfg) -> MPSendTxResult:
        mempool_tx_request = MPTxRequest(
            req_id=req_id, signature=signature, neon_tx=neon_tx, sender_tx_cnt=sender_tx_cnt,
            neon_tx_exec_cfg=neon_tx_exec_cfg
        )
        return self._pickable_data_client.send_data(mempool_tx_request)

    @_guard_conn
    @_reconnecting
    def get_pending_tx_nonce(self, req_id: str, sender: str) -> int:
        mempool_pending_tx_nonce_req = MPPendingTxNonceReq(req_id=req_id, sender=sender)
        return self._pickable_data_client.send_data(mempool_pending_tx_nonce_req)

    @_guard_conn
    @_reconnecting
    def get_pending_tx_by_hash(self, req_id: str, tx_hash: str) -> NeonTx:
        mempool_pending_tx_by_hash_req = MPPendingTxByHashReq(req_id=req_id, tx_hash=tx_hash)
        return self._pickable_data_client.send_data(mempool_pending_tx_by_hash_req)
