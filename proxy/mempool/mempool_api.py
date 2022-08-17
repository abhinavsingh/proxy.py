from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Tuple, Optional
from abc import ABC, abstractmethod
from asyncio import Task

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg


class IMPExecutor(ABC):

    @abstractmethod
    def submit_mp_request(self, mp_request: MPRequest) -> Tuple[int, Task]:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    # TODO: drop it away
    @abstractmethod
    def on_no_liquidity(self, resource_id: int):
        pass

    @abstractmethod
    def release_resource(self, resource_id: int):
        pass


class MPRequestType(IntEnum):
    SendTransaction = 0,
    GetLastTxNonce = 1,
    GetTxByHash = 2,
    Dummy = -1


@dataclass(order=True)
class MPRequest:
    req_id: str = field(compare=False)
    type: MPRequestType = field(compare=False, default=MPRequestType.Dummy)


@dataclass(eq=True, order=True)
class MPTxRequest(MPRequest):
    nonce: Optional[int] = field(compare=True, default=None)
    signature: Optional[str] = field(compare=False, default=None)
    neon_tx: Optional[NeonTx] = field(compare=False, default=None)
    neon_tx_exec_cfg: Optional[NeonTxExecCfg] = field(compare=False, default=None)
    sender_address: Optional[str] = field(compare=False, default=None)
    sender_tx_cnt: Optional[int] = field(compare=False, default=None)
    gas_price: Optional[int] = field(compare=False, default=None)

    def __post_init__(self):
        self.gas_price = self.neon_tx.gasPrice
        self.nonce = self.neon_tx.nonce
        self.sender_address = "0x" + self.neon_tx.sender()
        self.type = MPRequestType.SendTransaction
        tx_hash = self.signature
        self.log_str = f"MPTxRequest(hash={tx_hash[:10]}..., sender_address=0x{self.sender_address[:10]}..., nonce={self.nonce}, gas_price={self.gas_price})"


@dataclass
class MPPendingTxNonceReq(MPRequest):

    sender: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetLastTxNonce


@dataclass
class MPPendingTxByHashReq(MPRequest):
    tx_hash: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetTxByHash


class MPResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1,
    SolanaUnavailable = 2,
    Unspecified = 4,
    Dummy = -1


@dataclass
class MPTxResult:
    code: MPResultCode
    data: Any


@dataclass
class MPSendTxResult:
    success: bool
    last_nonce: Optional[int]
