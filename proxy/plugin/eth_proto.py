from ecdsa import SigningKey, SECP256k1, VerifyingKey
from sha3 import keccak_256
import json
from eth_keys import keys

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

def unpack(data):
    ch = data[0]
    if (ch <= 0x7F):
        return (ch, data[1:])
    elif (ch == 0x80):
        return (None, data[1:])
    elif (ch <= 0xB7):
        l = ch - 0x80
        return (data[1:1+l].tobytes(), data[1+l:])
    elif (ch <= 0xBF):
        lLen = ch - 0xB7
        l = int.from_bytes(data[1:1+lLen], byteorder='little')
        return (data[1+lLen:1+lLen+l].tobytes(), data[1+lLen+l:])
    elif (ch == 0xC0):
        return ((), data[1:])
    elif (ch <= 0xF7):
        l = ch - 0xC0
        lst = list()
        sub = data[1:1+l]
        while len(sub):
            (item, sub) = unpack(sub)
            lst.append(item)
        return (lst, data[1+l:])
    else:
        lLen = ch - 0xF7
        l = int.from_bytes(data[1:1+lLen], byteorder='little')
        lst = list()
        sub = data[1+lLen:1+lLen+l]
        while len(sub):
            (item, sub) = unpack(sub)
            lst.append(item)
        return (lst, data[1+lLen+l:])

def pack(data):
    if data == None:
        return (0x80).to_bytes(1,'big')
    if isinstance(data, str):
        return pack(data.encode('utf8'))
    elif isinstance(data, bytes):
        if len(data) <= 55:
            return (len(data)+0x80).to_bytes(1,'big')+data
        else:
            l = len(data)
            lLen = (l.bit_length()+7)//8
            return (0xB7+lLen).to_bytes(1,'big')+l.to_bytes(lLen,'big')+data
    elif isinstance(data, int):
        if data < 0x80:
            return data.to_bytes(1,'big')
        else:
            l = (data.bit_length()+7)//8
            return (l + 0x80).to_bytes(1,'big') + data.to_bytes(l,'big')
        pass
    elif isinstance(data, list) or isinstance(data, tuple):
        if len(data) == 0:
            return (0xC0).to_bytes(1,'big')
        else:
            res = bytearray()
            for d in data:
                res += pack(d)
            l = len(res)
            if l <= 0x55:
                return (l + 0xC0).to_bytes(1,'big')+res
            else:
                lLen = (l.bit_length()+7)//8
                return (lLen+0xF7).to_bytes(1,'big') + l.to_bytes(lLen,'big') + res
    else:
        raise Exception("Unknown type {} of data".format(str(type(data))))

def getInt(a):
    if isinstance(a, int): return a
    if isinstance(a, bytes): return int.from_bytes(a, 'big')
    if a == None: return a
    raise Exception("Invalid convertion from {} to int".format(a))

class Trx:
    def __init__(self):
        self.nonce = None
        self.gasPrice = None
        self.gasLimit = None
        self.toAddress = None
        self.value = None
        self.callData = None
        self.v = None
        self.r = None
        self.s = None

    @classmethod
    def fromString(cls, s):
        t = Trx()
        (unpacked, data) = unpack(memoryview(s))
        (nonce, gasPrice, gasLimit, toAddress, value, callData, v, r, s) = unpacked
        t.nonce = getInt(nonce)
        t.gasPrice = getInt(gasPrice)
        t.gasLimit = getInt(gasLimit)
        t.toAddress = toAddress
        t.value = getInt(value)
        t.callData = callData
        t.v = getInt(v)
        t.r = getInt(r)
        t.s = getInt(s)
        return t
    
    def chainId(self):
        # chainid*2 + 35  xxxxx0 + 100011   xxxx0 + 100010 +1
        # chainid*2 + 36  xxxxx0 + 100100   xxxx0 + 100011 +1
        return (self.v-1)//2 - 17

    def __str__(self):
        return pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            self.v,
            self.r.to_bytes(32,'big') if self.r else None,
            self.s.to_bytes(32,'big') if self.s else None)
        ).hex()

    def hash(self, chainId=None):
        trx = pack((
            self.nonce,
            self.gasPrice,
            self.gasLimit,
            self.toAddress,
            self.value,
            self.callData,
            chainId or self.chainId(), None, None))
        return keccak_256(trx).digest()

    def sender(self):
        msgHash = self.hash()
        sig = keys.Signature(vrs=[1 if self.v%2==0 else 0, self.r, self.s])
        pub = sig.recover_public_key_from_msg_hash(msgHash)
        return pub.to_canonical_address().hex()

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
