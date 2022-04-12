from __future__ import annotations
from sha3 import keccak_256
import rlp
from eth_keys import keys
from typing import Optional

public = '0x2377BB12320F46F0B9E30EBFB941121352716f2C'
private = '0x886d5b4ce9465473701bf394b1b0b217548c57576436864fcbc1f554033a0680'
trx = '0xF86B80850BA43B7400825208947917bc33eea648809c285607579c9919fb864f8f8703BAF82D03A0008025A0067940651530790861714b2e8fd8b080361d1ada048189000c07a66848afde46A069b041db7c29dbcc6becf42017ca7ac086b12bd53ec8ee494596f790fb6a0a69'
'''
0xf8 73
80 - nonce
85 3374a06200 - gasPrice
82 5208 - gasLimit
94 2377bb12320f46f0b9e30ebfb941121352716f2c - toAddress
89 055de6a779bbac0000 - value
80 - callData
86 02e92be91e86 - v
a0 602af7bd4ac154a568c2d1478b23d697390e035cd72250e77a0d56ce2c4a63db - r
a0 5d09ca05a62935d6c2a04bfa5bfa1cb46bfcb59e3a115e0c8cceca807efb778b - s
'''


class InvalidTrx(Exception):
    pass


class NoChainTrx(rlp.Serializable):
    fields = (
        ('nonce', rlp.codec.big_endian_int),
        ('gasPrice', rlp.codec.big_endian_int),
        ('gasLimit', rlp.codec.big_endian_int),
        ('toAddress', rlp.codec.binary),
        ('value', rlp.codec.big_endian_int),
        ('callData', rlp.codec.binary),
    )

    @classmethod
    def fromString(cls, s) -> NoChainTrx:
        return rlp.decode(s, NoChainTrx)


class Trx(rlp.Serializable):
    fields = (
        ('nonce', rlp.codec.big_endian_int),
        ('gasPrice', rlp.codec.big_endian_int),
        ('gasLimit', rlp.codec.big_endian_int),
        ('toAddress', rlp.codec.binary),
        ('value', rlp.codec.big_endian_int),
        ('callData', rlp.codec.binary),
        ('v', rlp.codec.big_endian_int),
        ('r', rlp.codec.big_endian_int),
        ('s', rlp.codec.big_endian_int)
    )

    secpk1n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    null_address = b'\xff' * 20

    def __init__(self, *args, **kwargs):
        rlp.Serializable.__init__(self, *args, **kwargs)
        self._msg = None

    @classmethod
    def fromString(cls, s) -> Trx:
        try:
            return rlp.decode(s, Trx)
        except rlp.exceptions.ObjectDeserializationError as err:
            if (not err.list_exception) or (len(err.list_exception.serial) != 6):
                raise

            tx = NoChainTrx.fromString(s)
            return cls._copy_from_nochain_tx(tx)

    @classmethod
    def _copy_from_nochain_tx(cls, nochain_tx: NoChainTrx) -> Trx:
        value_list = []
        for value in nochain_tx:
            value_list.append(value)
        value_list += [0, 0, 0]
        return cls(*value_list)

    def chainId(self) -> Optional[int]:
        if self.v in (0, 27, 28):
            return None
        elif self.v >= 37:
            # chainid*2 + 35  xxxxx0 + 100011   xxxx0 + 100010 +1
            # chainid*2 + 36  xxxxx0 + 100100   xxxx0 + 100011 +1
            return ((self.v - 1) // 2) - 17
        else:
            raise InvalidTrx(f"Invalid V value {self.v}")

    def _unsigned_msg(self) -> bytes:
        chain_id = self.chainId()
        if chain_id is None:
            return rlp.encode((self.nonce, self.gasPrice, self.gasLimit, self.toAddress, self.value, self.callData))
        else:
            return rlp.encode((self.nonce, self.gasPrice, self.gasLimit, self.toAddress, self.value, self.callData,
                               chain_id, 0, 0), Trx)

    def unsigned_msg(self) -> bytes:
        if self._msg is None:
            self._msg = self._unsigned_msg()
        return self._msg

    def _signature(self) -> keys.Signature:
        return keys.Signature(vrs=[1 if self.v % 2 == 0 else 0, self.r, self.s])

    def signature(self) -> bytes:
        return self._signature().to_bytes()

    def _sender(self) -> bytes:
        if self.r == 0 and self.s == 0:
            return self.null_address
        elif self.v in (0, 27, 28):
            pass
        elif self.v >= 37:
            vee = self.v - self.chainId() * 2 - 8
            assert vee in (27, 28)
        else:
            raise InvalidTrx(f"Invalid V value {self.v}")

        if self.r >= self.secpk1n or self.s >= self.secpk1n or self.r == 0 or self.s == 0:
            raise InvalidTrx(f"Invalid signature values: r={self.r} s={self.s}!")

        sighash = keccak_256(self._unsigned_msg()).digest()
        sig = self._signature()
        pub = sig.recover_public_key_from_msg_hash(sighash)

        return pub.to_canonical_address()

    def sender(self) -> str:
        return self._sender().hex()

    def hash_signed(self) -> bytes:
        return keccak_256(rlp.encode((self.nonce, self.gasPrice, self.gasLimit,
                                      self.toAddress, self.value, self.callData,
                                      self.v, self.r, self.s))).digest()

    def contract(self) -> Optional[str]:
        if self.toAddress:
            return None
        contract_addr = rlp.encode((self._sender(), self.nonce))
        return keccak_256(contract_addr).digest()[-20:].hex()


#class JsonEncoder(json.JSONEncoder):
#    def default(self, obj):
#        if isinstance(obj, bytes):
#            return obj.hex()
#        return json.JSONEncoder.default(self.obj)
#
#trx = '0xf8af098539f98e7a0082bfd194b80102fd2d3d1be86823dd36f9c783ad0ee7d89880b844a9059cbb000000000000000000000000c1566af4699928fdf9be097ca3dc47ece39f8f8e00000000000000000000000000000000000000000000000000000000000000328602e92be91e86a0e2c683a38606033cf416cca55575b4080465f1a275aff080b2af1a264b24d56ca02e48a4cb63d8549610d070b02e272ab6a3a680e677c7d7f51045a9cbcf218f0d'
#trx = '0xf8af098539f98e7a0082bfd194b80102fd2d3d1be86823dd36f9c783ad0ee7d89880b844a9059cbb000000000000000000000000c1566af4699928fdf9be097ca3dc47ece39f8f8e00000000000000000000000000000000000000000000000000000000000000328602e92be91e86a0e2c683a38606033cf416cca55575b4080465f1a275aff080b2af1a264b24d56ca02e48a4cb63d8549610d070b02e272ab6a3a680e677c7d7f51045a9cbcf218f0d'
#trx = '0xf87202853946be1c0082520894c1566af4699928fdf9be097ca3dc47ece39f8f8e880de0b6b3a7640000808602e92be91e85a06f350382938df92b987681de78d81f0490ee1d26b18ea968ae42ee4a800711a6a0641672e91b735bd6badd2c51b6a6ecdcd740b78c8bf581aa3f1431cd0f8c02f3'
#
#_trx = Trx.fromString(bytearray.fromhex(trx[2:]))
#print(json.dumps(_trx.__dict__, cls=JsonEncoder, indent=3))
#print(str(_trx))
#print(trx[2:])
#
#msgHash = _trx.hash()
#sig = keys.Signature(vrs=[1 if _trx.v%2==0 else 0, _trx.r, _trx.s])
#pub = sig.recover_public_key_from_msg_hash(msgHash)
#print('SENDER', pub.to_canonical_address().hex())
#print("VERIFY", sig.verify_msg_hash(msgHash, pub))
