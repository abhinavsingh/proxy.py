from __future__ import annotations

import sys
import os

from proxy.common_neon.keys_storage import KeyStorage


class AccountHandler:
    def __init__(self):
        self.command = 'account'
        self._storage = None

    @staticmethod
    def init_args_parser(parsers) -> AccountHandler:
        h = AccountHandler()
        h.root_parser = parsers.add_parser(h.command)
        h.subparsers = h.root_parser.add_subparsers(title='command', dest='subcommand', description='valid commands')
        h.new_parser = h.subparsers.add_parser('new')
        h.list_parser = h.subparsers.add_parser('list')
        h.list_parser.add_argument('--private-key', action='store_true')
        h.import_parser = h.subparsers.add_parser('import')
        h.import_parser.add_argument('--private-key', type=str, nargs=1, help='private-key as parameterag')
        h.import_parser.add_argument('file', metavar='file', type=str, nargs='?', help='an input file with private key')
        return h

    def execute(self, args):
        self._storage = KeyStorage()

        if args.subcommand == 'new':
            self._execute_new(args)
        elif args.subcommand == 'import':
            self._execute_import(args)
        elif args.subcommand == 'list':
            self._execute_list(args)
        else:
            print(f'Unknown command {args.subcommand} for account', file=sys.stderr)

    def _execute_new(self, args):
        eth_address = self._storage.generate_new()
        print(f'Address: {"{"+str(eth_address)[2:]+"}"}')

    def _execute_import(self, args):
        if args.file:
            self._execute_import_file(args)
        elif len(args.private_key):
            self._execute_import_key(args)
        else:
            print(f"You should specify one of <file> or <private-key>", file=sys.stderr)

    def _execute_import_file(self, args):
        file = args.file
        if not os.path.isfile(file):
            print(f"File {file} doesn't exist", file=sys.stderr)
            return

        with open(file, 'r') as f:
            line = f.read()
            pk_key = bytes.fromhex(line)
            eth_address = self._storage.import_private_key(pk_key)
            print(f'Address: {"{" + str(eth_address)[2:] + "}"}')

    def _execute_import_key(self, args):
        pk_key = bytes.fromhex(args.private_key[0])
        eth_address = self._storage.import_private_key(pk_key)
        print(f'Address: {"{" + str(eth_address)[2:] + "}"}')

    def _execute_list(self, args):
        eth_address_list = self._storage.get_list()
        path = self._storage.storage_path()
        for i, eth_address in enumerate(sorted(eth_address_list, key=lambda x: str(x))):
            s = f'Account #{i}: {"{"}{str(eth_address)[2:]}{"}"} keystore:///{path}'
            if args.private_key:
                s += f' private: {"{"}{str(eth_address.private)}{"}"}'

            print(s)
