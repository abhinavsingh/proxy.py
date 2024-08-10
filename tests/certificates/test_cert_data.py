# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any


# pylint: disable=line-too-long
test_cert_bytes = b"0\x82\x03\xa30\x82\x02\x8b\xa0\x03\x02\x01\x02\x02\x14PE\x01\x8c\xa6\xea\xd8#\xcf\x90\xb0D\xc7\x04\xde\x9b9Y\xf3 0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000a1\x0b0\t\x06\x03U\x04\x06\x13\x02as1\x0b0\t\x06\x03U\x04\x08\x0c\x02as1\x0b0\t\x06\x03U\x04\x07\x0c\x02as1\x0b0\t\x06\x03U\x04\n\x0c\x02as1\x0b0\t\x06\x03U\x04\x0b\x0c\x02as1\x0b0\t\x06\x03U\x04\x03\x0c\x02as1\x110\x0f\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x02as0\x1e\x17\r240429125057Z\x17\r250429125057Z0a1\x0b0\t\x06\x03U\x04\x06\x13\x02as1\x0b0\t\x06\x03U\x04\x08\x0c\x02as1\x0b0\t\x06\x03U\x04\x07\x0c\x02as1\x0b0\t\x06\x03U\x04\n\x0c\x02as1\x0b0\t\x06\x03U\x04\x0b\x0c\x02as1\x0b0\t\x06\x03U\x04\x03\x0c\x02as1\x110\x0f\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x02as0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xee\xcbU\xe3\xc4]\x83\xb9\x9d\xb1(v0\x18\x18\xc3\x00\x96\xc0\x0f\xc29\x84\xe7/W\xc7\x0b\xec\xdf\x9d-\xec\xd9\x876\xe5m\xda\x96\xea\xb0\xc6\x00\x7f\xb6\x93;\xd6\x1bK`\xd4Hc<\xa0g\xe5Q[\xe3\xe1\xd1DD5\x9b\x12\xdf\xd0\xd0\xc6X\xc9\x98\xc9\xb1\x81\xf5\xa2\x12\xaa\xc1\xb0\x80\xe8)R\xa7\xed\xe3P6\x82\x05\xbcA4\x91\xbcs?\xc2\xf2\xfd-\xe65'};\xa7E\xb2yN\x0fiO7\x82-`CX\xdb\xe0\x9c\xd7\x8e\x00N\nAu\xac/\xb3o\xcaG;\xa4\x8d\xca\x92\xe3F\x96\xe5\xbd\x1dq\xf6\xa5\x9f\xc5@I=\xfc\x1cl\x81\xb3y\x93FaPa^\x08\x0f\x80t\xb8J\xfd\xb8]\xd52\xf5\x9bE\xe8J:\x08\x8c\x98m0\xba\x85\x1b\xb6\x97\xe5\xba4\xe3nU\xa5\xc7\xeb\xde_z\x1a(j\xa7\xeb\x8a\xb4\xe1'?\x91\x80MhG=y\xc7\xf1|\xcaJ@\xae\xc4'\xd6\xd6}L\xf4\x91NV`\x98\x80\xef%\xa2hq\x05s\x02\x03\x01\x00\x01\xa3S0Q0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xc6\xa4,\xe5\xe3\x15j\x18\x15@Xw!\xdd\xbf\xc6\xe5\xf0vG0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xc6\xa4,\xe5\xe3\x15j\x18\x15@Xw!\xdd\xbf\xc6\xe5\xf0vG0\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\xacx\xeb\x02\x8a\xd3\x966\xb73\xfb\n\x1eb\ng\xda\x84\x18\x97P\xb4\x7f\x8a\xbd\x82\xf3\x1b\xe8k%\xcc\x0f\xbd\x7fB\xb9\x1df|-k\x01\xf3\x89\x08r\xb9\x93\xf5?Z\x16\xff\x0f\x97\x91b#\xef$I\x11\x9e\x16\xb2J\x97\xd1\x0e\xd6\xabD\xca@\xe7\xb3\xbe\x84S\x1e\xdb;\x9b\xc4\xf4\x18\xf4\x9a\x1b\xcej\xe0qmx\xe4N?K\n.p\xa8\xa6\xfa\xb0\xf7y\xe8\x0f\xbd\x0c216\xb0\xa1d\x1f\x7f3\xa1l?\xbe\x9a\x06\xed]\x1a\x00\xab\xb4e\x13:\x17\x1b\x88\x8e\xcaqp\"\x8f\xa6\xf7\x06J?`\xe0\xf7\xce\xf8K\x08\x15\x18\xa1\xc4\xb5\xd9hB\xb0\xc6\\\xae?\xa9\x83FL\x8cm\xd1\xad^\xf0\xa5:\x8e\x97\x07\xd2\xd0l\x0e\x9d\x01\xa00c)\xae\xd0@\xefr\xe7,\xb7[\xd3H\xfe1\xfb\xa9|\xd0\xac\xc6i\x98\xe5\xd5\xd1\xf2\x97<\xf9\xe1?=\x93\xfaM\x86\xa2\x9dy\xdeZj\x93&\xa6\x84d\x07a\xbf\xd6\xdde\xaa)\t\xd6\x0e\x99\x85K"


def mock_cert(_: Any) -> Any:
    return test_cert_bytes


cert_dict = {
    'subject': (
        (('countryName', 'as'),),
        (('stateOrProvinceName', 'as'),),
        (('localityName', 'as'),),
        (('organizationName', 'as'),),
        (('organizationalUnitName', 'as'),),
        (('commonName', 'as'),),
        (('emailAddress', 'as'),),
    ),
    'issuer': (
        (('countryName', 'as'),),
        (('stateOrProvinceName', 'as'),),
        (('localityName', 'as'),),
        (('organizationName', 'as'),),
        (('organizationalUnitName', 'as'),),
        (('commonName', 'as'),),
        (('emailAddress', 'as'),),
    ),
    'version': 3,
    'serialNumber': '5045018CA6EAD823CF90B044C704DE9B3959F320',
    'notBefore': 'Apr 29 12:50:57 2024 GMT',
    'notAfter': 'Apr 29 12:50:57 2025 GMT',
}
