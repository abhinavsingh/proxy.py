from __future__ import annotations

import sys


class OperatorHandler:
    def __init__(self):
        self.command = 'operator'

    @staticmethod
    def init_args_parser(parsers) -> OperatorHandler:
        h = OperatorHandler()
        h.root_parser = parsers.add_parser(h.command)
        return h

    def execute(self):
        print(f'Not implemented yet', file=sys.stderr)
