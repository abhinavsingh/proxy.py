import sys

import atheris

from .neon_rcp_api_worker import eth_getBalance


def TestEthgetBalance(data, data2):
    try:
        _ = eth_getBalance(account=data, tag=data2)
    except ValueError:
        None


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestEthFunctions)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
