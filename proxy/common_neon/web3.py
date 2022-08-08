from web3 import Web3
from web3.module import Module
from web3.method import Method
from web3.providers.base import BaseProvider
from typing import Optional, Tuple
from web3.types import RPCEndpoint
from proxy.common_neon.eth_proto import Trx

class Neon(Module):
    neon_emulate = RPCEndpoint("neon_emulate")

    def emulate_munger(
        self,
        trx: bytearray
    ):
        return ([bytes(trx).hex()])

    emulate = Method(
        neon_emulate,
        mungers=[emulate_munger],
    )

    neon_getEvmParams = RPCEndpoint("neon_getEvmParams")

    getEvmParams = Method(
        neon_getEvmParams,
        mungers=[],
    )


class NeonWeb3(Web3):
    neon: Neon

    def __init__(self, provider:  Optional[BaseProvider] = None):
        super().__init__(provider)
        setattr(self, "neon", Neon(self))
