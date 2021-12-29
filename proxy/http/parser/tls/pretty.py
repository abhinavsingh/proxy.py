import binascii


def pretty_hexlify(raw: bytes) -> str:
    hexlified = binascii.hexlify(raw).decode('utf-8')
    return ' '.join([hexlified[i: i+2] for i in range(0, len(hexlified), 2)])
