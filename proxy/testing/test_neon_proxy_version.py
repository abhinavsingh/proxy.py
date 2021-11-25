import unittest
import os
import requests
import json
import inspect

from proxy.plugin.solana_rest_api import NEON_PROXY_PKG_VERSION, NEON_PROXY_REVISION

proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
headers = {'Content-type': 'application/json'}


def get_line_number():
    cf = inspect.currentframe()
    return cf.f_back.f_lineno


class TestNeonProxyVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def test_01_neon_proxy_version(self):
        print("https://github.com/neonlabsorg/proxy-model.py/issues/320")
        response = json.loads(requests.post(
            proxy_url, headers=headers,
            data=json.dumps({"jsonrpc": "2.0",
                             "id": get_line_number(),
                             "method": "neon_proxy_version",
                             "params": []
                             })).text)
        print('response:', response)
        neon_proxy_version = response['result']
        print('neon_proxy_version:', neon_proxy_version)
        self.assertEqual(neon_proxy_version, 'Neon-proxy/v' + NEON_PROXY_PKG_VERSION + '-' + NEON_PROXY_REVISION)


if __name__ == '__main__':
    unittest.main()
