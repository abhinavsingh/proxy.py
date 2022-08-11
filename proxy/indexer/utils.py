from __future__ import annotations

import statistics

from typing import Dict, Union, Callable, List

from ..common_neon.environment_data import INDEXER_LOG_SKIP_COUNT


def check_error(trx):
    if 'meta' in trx and 'err' in trx['meta'] and trx['meta']['err'] is not None:
        return True
    return False


class MetricsToLogger:
    def __init__(self):
        self._counter: int = 0
        self._item_list_dict: Dict[str, List[Union[int, float]]] = {}
        self._item_value_dict: Dict[str, int] = {}

    def _reset(self):
        self._counter = 0
        self._item_list_dict.clear()

    def print(self, logger: Callable[[str], None],
              list_value_dict: Dict[str, Union[int, float]],
              latest_value_dict: Dict[str, int]):
        for key, value in list_value_dict.items():
            metric_list = self._item_list_dict.setdefault(key, [])
            metric_list.append(value)
        for key, value in latest_value_dict.items():
            self._item_value_dict[key] = value
        self._counter += 1

        if self._counter % INDEXER_LOG_SKIP_COUNT != 0:
            return

        msg = ''
        for key, value_list in self._item_list_dict.items():
            msg += f' {key} avg: {statistics.mean(value_list):.2f}'
            msg += f' min: {min(value_list):.2f}'
            msg += f' max: {max(value_list):.2f};'
        for key, value in self._item_value_dict.items():
            msg += f' {key}: {value};'
        logger(msg)
        self._reset()
