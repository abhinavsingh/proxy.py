import os
import time
import traceback
from logged_groups import logged_group

from ..common_neon.solana_interactor import SolanaInteractor

from ..common_neon.environment_data import FINALIZED


@logged_group("neon.Indexer")
class IndexerBase:
    def __init__(self, solana: SolanaInteractor, last_slot: int):
        self._solana = solana
        self._last_slot = self._init_last_slot('receipt', last_slot)

    def _init_last_slot(self, name: str, last_known_slot: int) -> int:
        """
        This function allow to skip some part of history.
        - LATEST - start from the last block slot from Solana
        - CONTINUE - continue from the last parsed slot of from latest
        - NUMBER - first start from the number, then continue from last parsed slot
        """
        last_known_slot = 0 if not isinstance(last_known_slot, int) else last_known_slot
        latest_slot = self._solana.get_block_slot(FINALIZED)
        start_int_slot = 0
        name = f'{name} slot'

        START_SLOT = os.environ.get('START_SLOT', 0)
        start_slot = START_SLOT
        if start_slot not in ['CONTINUE', 'LATEST']:
            try:
                start_int_slot = min(int(start_slot), latest_slot)
            except (Exception,):
                start_int_slot = 0

        if start_slot == 'CONTINUE':
            if last_known_slot > 0:
                self.info(f'START_SLOT={START_SLOT}: started the {name} from previous run {last_known_slot}')
                return last_known_slot
            else:
                self.info(f'START_SLOT={START_SLOT}: forced the {name} from the latest Solana slot')
                start_slot = 'LATEST'

        if start_slot == 'LATEST':
            self.info(f'START_SLOT={START_SLOT}: started the {name} from the latest Solana slot {latest_slot}')
            return latest_slot

        if start_int_slot < last_known_slot:
            self.info(f'START_SLOT={START_SLOT}: started the {name} from previous run, ' +
                      f'because {start_int_slot} < {last_known_slot}')
            return last_known_slot

        self.info(f'START_SLOT={START_SLOT}: started the {name} from {start_int_slot}')
        return start_int_slot

    def run(self):
        while True:
            try:
                self.process_functions()
            except Exception as err:
                err_tb = "".join(traceback.format_tb(err.__traceback__))
                self.warning('Exception on transactions processing. ' +
                             f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            time.sleep(0.05)

    def process_functions(self) -> None:
        pass
