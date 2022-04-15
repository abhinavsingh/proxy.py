from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, start_http_server

from ..common_neon.data import NeonTxStatData

from .proxy_metrics_interface import StatisticsExporter

class IndexerStatistics(StatisticsExporter):
    registry = CollectorRegistry()
    TX_SOL_SPENT = Histogram(
        'tx_sol_spent', 'How many lamports being spend in Neon transaction per iteration',
        registry=registry
    )
    TX_NEON_INCOME = Histogram(
        'tx_neon_income', 'Neon payed for transaction',
        registry=registry
    )
    TX_BPF_PER_ITERATION = Histogram(
        'tx_bpf_per_iteration', 'How many BPF cycles was used in each iteration',
        registry=registry
    )
    TX_STEPS_PER_ITERATION = Histogram(
        'tx_steps_per_iteration', 'How many steps was used in each iteration',
        registry=registry
    )
    TX_COUNT = Counter('tx_count', 'Count of Neon transactions were completed (independent on status)', registry=registry)
    TX_CANCELED = Counter('tx_canceled', 'Count of Neon transactions were canceled', registry=registry)
    COUNT_TX_COUNT_BY_TYPE = Counter(
        'count_tx_count_by_type', 'Count of transactions by type(single\iter\iter w holder)',
        ['type'],
        registry=registry
    )
    COUNT_SOL_TX_PER_NEON_TX = Histogram(
        'count_sol_tx_per_neon_tx', 'Count of solana txs within by type(single\iter\iter w holder)',
        ['type'],
        registry=registry
    )
    POSTGRES_AVAILABILITY = Gauge('postgres_availability', 'Postgres availability', registry=registry)
    SOLANA_RPC_HEALTH = Gauge('solana_rpc_health', 'Solana Node status', registry=registry)

    def __init__(self, do_work: bool = True):
        self.do_work = do_work
        if self.do_work:
            start_http_server(8887, registry=self.registry)

    def on_neon_tx_result(self, tx_stat: NeonTxStatData):
        for instruction_info in tx_stat.instructions:
            sol_tx_hash, sol_spent, steps, bpf = instruction_info
            self.stat_commit_tx_sol_spent(tx_stat.neon_tx_hash, sol_tx_hash, sol_spent)
            self.stat_commit_tx_steps_bpf(tx_stat.neon_tx_hash, sol_tx_hash, steps, bpf)
        self.stat_commit_tx_count(tx_stat.is_canceled)
        self.stat_commit_tx_neon_income(tx_stat.neon_tx_hash, tx_stat.neon_income)
        self.stat_commit_count_sol_tx_per_neon_tx(tx_stat.tx_type, len(tx_stat.instructions))

    def stat_commit_tx_sol_spent(self, neon_tx_hash: str, sol_tx_hash: str, sol_spent: int):
        if self.do_work:
            self.TX_SOL_SPENT.observe(sol_spent)

    def stat_commit_tx_neon_income(self, neon_tx_hash: str, neon_income: int):
        if self.do_work:
            self.TX_NEON_INCOME.observe(neon_income)

    def stat_commit_tx_steps_bpf(self, neon_tx_hash: str, sol_tx_hash: str, steps: int, bpf: int):
        if self.do_work:
            if bpf:
                self.TX_BPF_PER_ITERATION.observe(bpf)
            if steps:
                self.TX_STEPS_PER_ITERATION.observe(steps)

    def stat_commit_tx_count(self, canceled: bool = False):
        if self.do_work:
            self.TX_COUNT.inc()
            if canceled:
                self.TX_CANCELED.inc()

    def stat_commit_count_sol_tx_per_neon_tx(self, type: str, sol_tx_count: int):
        if self.do_work:
            self.COUNT_TX_COUNT_BY_TYPE.labels(type).inc()
            self.COUNT_SOL_TX_PER_NEON_TX.labels(type).observe(sol_tx_count)

    def stat_commit_postgres_availability(self, status: bool):
        if self.do_work:
            self.POSTGRES_AVAILABILITY.set(1 if status else 0)

    def stat_commit_solana_rpc_health(self, status: bool):
        if self.do_work:
            self.SOLANA_RPC_HEALTH.set(1 if status else 0)

    def stat_commit_request_and_timeout(self, *args):
        pass

    def stat_commit_tx_begin(self, *args):
        pass

    def stat_commit_tx_end_success(self, *args):
        pass

    def stat_commit_tx_end_failed(self, *args):
        pass

    def stat_commit_tx_balance_change(self, *args):
        pass

    def stat_commit_operator_sol_balance(self, *args):
        pass

    def stat_commit_operator_neon_balance(self, *args):
        pass

    def stat_commit_create_resource_account(self, *args):
        pass

    def stat_commit_gas_parameters(self, *args):
        pass
