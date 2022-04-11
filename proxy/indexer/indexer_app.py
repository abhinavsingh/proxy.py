from logged_groups import logged_group

from ..environment import EVM_LOADER_ID, SOLANA_URL
from ..statistics_exporter.prometheus_indexer_exporter import IndexerStatistics
from ..common_neon.data import NeonTxStatData
from .indexer import Indexer
from .i_inidexer_user import IIndexerUser


@logged_group("neon.Indexer")
class IndexerApp(IIndexerUser):

    def __init__(self, solana_url: str):
        self.neon_statistics = IndexerStatistics()
        indexer = Indexer(solana_url, self)
        indexer.run()

    def on_neon_tx_result(self, tx_stat: NeonTxStatData):
        self.neon_statistics.on_neon_tx_result(tx_stat)


    def on_db_status(self, neon_db_status: bool):
        self.neon_statistics.stat_commit_postgres_availability(neon_db_status)

    def on_solana_rpc_status(self, solana_status: bool):
        self.neon_statistics.stat_commit_solana_rpc_health(solana_status)


@logged_group("neon.Indexer")
def run_indexer(solana_url, *, logger):
    logger.info(f"""Running indexer with params:
        solana_url: {solana_url},
        evm_loader_id: {EVM_LOADER_ID}""")

    IndexerApp(solana_url)


if __name__ == "__main__":
    solana_url = SOLANA_URL
    run_indexer(solana_url)
