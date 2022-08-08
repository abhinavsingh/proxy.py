from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Tuple, Optional
from abc import ABC, abstractmethod
from asyncio import Task

from ..common_neon.eth_proto import Trx as NeonTx
from ..common_neon.data import NeonTxExecCfg, NeonEmulatingResult


class IMPExecutor(ABC):

    @abstractmethod
    def submit_mp_request(self, mp_reqeust: MPRequest) -> Tuple[int, Task]:
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
    GetTrxCount = 1,
    Dummy = -1


@dataclass(order=True)
class MPRequest:
    req_id: int = field(compare=False)
    type: MPRequestType = field(compare=False, default=MPRequestType.Dummy)


@dataclass(eq=True, order=True)
class MPTxRequest(MPRequest):
    nonce: int = field(compare=True, default=None)
    signature: str = field(compare=False, default=None)
    neon_tx: NeonTx = field(compare=False, default=None)
    neon_tx_exec_cfg: Optional[NeonTxExecCfg] = None
    sender_address: str = field(compare=False, default=None)
    gas_price: int = field(compare=False, default=None)

    def __post_init__(self):
        self.gas_price = self.neon_tx.gasPrice
        self.nonce = self.neon_tx.nonce
        self.sender_address = "0x" + self.neon_tx.sender()
        self.type = MPRequestType.SendTransaction
        hash = "0x" + self.neon_tx.hash_signed().hex()
        self.log_str = f"MPTxRequest(hash={hash[:10]}..., sender_address=0x{self.sender_address[:10]}..., nonce={self.nonce}, gas_price={self.gas_price})"

@dataclass
class MPPendingTxCountReq(MPRequest):

    sender: str = None

    def __post_init__(self):
        self.type = MPRequestType.GetTrxCount


class MPResultCode(IntEnum):
    Done = 0
    BlockedAccount = 1,
    SolanaUnavailable = 2,
    PendingTxError = 3,
    Unspecified = 4,
    Dummy = -1


@dataclass
class MPTxResult:
    code: MPResultCode
    data: Any
