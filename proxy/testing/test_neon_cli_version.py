import unittest
import os
import requests
import json
import inspect

from ..common_neon.environment_utils import neon_cli

proxy_url = os.environ.get('PROXY_URL', 'http://localhost:9090/solana')
headers = {'Content-type': 'application/json'}


def get_line_number():
    cf = inspect.currentframe()
    return cf.f_back.f_lineno


class TestNeonProxyVersion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def test_01_neon_cli_version(self):
        print("https://github.com/neonlabsorg/proxy-model.py/issues/319")
        response = json.loads(requests.post(
            proxy_url, headers=headers,
            data=json.dumps({"jsonrpc": "2.0",
                             "id": get_line_number(),
                             "method": "neon_cli_version",
                             "params": []
                             })).text)
        print('response:', response)
        neon_cli_version = response['result']
        print('neon_cli_version:', neon_cli_version)
        self.assertEqual(neon_cli_version, neon_cli().version())


if __name__ == '__main__':
    unittest.main()
