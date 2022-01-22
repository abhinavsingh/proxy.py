import base58
from logged_groups import logged_group
import traceback

try:
    from utils import LogDB, NeonTxInfo, NeonTxResultInfo, SolanaIxSignInfo, FINALIZED
    from blocks_db import SolanaBlocksDB, SolanaBlockDBInfo
    from transactions_db import NeonTxsDB, NeonTxDBInfo
    from sql_dict import SQLDict
except ImportError:
    from .utils import LogDB, NeonTxInfo, NeonTxResultInfo, SolanaIxSignInfo, FINALIZED
    from .blocks_db import SolanaBlocksDB, SolanaBlockDBInfo
    from .transactions_db import NeonTxsDB, NeonTxDBInfo
    from .sql_dict import SQLDict


@logged_group("neon.indexer")
class IndexerDB:
    def __init__(self, client):
        self._logs_db = LogDB()
        self._blocks_db = SolanaBlocksDB()
        self._txs_db = NeonTxsDB()
        self._client = client

        self._constants = SQLDict(tablename="constants")
        for k in ['last_block_slot', 'last_block_height', 'min_receipt_slot']:
            if k not in self._constants:
                self._constants[k] = 0

    def submit_transaction(self, neon_tx: NeonTxInfo, neon_res: NeonTxResultInfo, used_ixs: [SolanaIxSignInfo]):
        try:
            block = self.get_block_by_slot(neon_res.slot)
            if block.hash is None:
                self.critical(f'Unable to submit transaction {neon_tx.sign} because slot {neon_res.slot} not found')
                return
            self.debug(f'{neon_tx} {neon_res} {block}')
            if neon_res.logs:
                for rec in neon_res.logs:
                    rec['transactionHash'] = neon_tx.sign
                    rec['blockHash'] = block.hash
                    rec['blockNumber'] = hex(block.height)
                self._logs_db.push_logs(neon_res.logs, block)
            tx = NeonTxDBInfo(neon_tx=neon_tx, neon_res=neon_res, block=block, used_ixs=used_ixs)
            self.debug(f'submit_transaction NeonTxDBInfo {tx}')
            self._txs_db.set_tx(tx)
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error('Exception on submitting transaction. ' +
                           f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def _fill_block_from_net(self, block: SolanaBlockDBInfo):
        opts = {"commitment": "confirmed", "transactionDetails": "signatures", "rewards": False}
        net_block = self._client._provider.make_request("getBlock", block.slot, opts)
        if (not net_block) or ('result' not in net_block):
            return block

        net_block = net_block['result']
        block.hash = '0x' + base58.b58decode(net_block['blockhash']).hex()
        block.height = net_block['blockHeight']
        block.signs = net_block['signatures']
        block.parent_hash = '0x' + base58.b58decode(net_block['previousBlockhash']).hex()
        block.time = net_block['blockTime']
        block.finalized = block.finalized if block.finalized else ("confirmed" == FINALIZED)
        self.debug(f'{block}')
        self._blocks_db.set_block(block)
        return block

    def get_block_by_slot(self, slot) -> SolanaBlockDBInfo:
        block = self._blocks_db.get_block_by_slot(slot)
        if not block.hash:
            self._fill_block_from_net(block)
        return block

    def get_full_block_by_slot(self, slot) -> SolanaBlockDBInfo:
        block = self._blocks_db.get_full_block_by_slot(slot)
        if not block.parent_hash:
            self._fill_block_from_net(block)
        return block

    def get_last_block_slot(self):
        return self._constants['last_block_slot']

    def get_last_block_height(self):
        return self._constants['last_block_height']

    def get_latest_block_height(self):
        return self._blocks_db.get_latest_block_height()

    def set_last_slot_height(self, slot, height):
        self._constants['last_block_slot'] = slot
        self._constants['last_block_height'] = height

    def fill_block_height(self, number, slots):
        self._blocks_db.fill_block_height(number, slots)

    def get_min_receipt_slot(self):
        return self._constants['min_receipt_slot']

    def set_min_receipt_slot(self, slot):
        self._constants['min_receipt_slot'] = slot

    def get_logs(self, fromBlock, toBlock, address, topics, blockHash):
        return self._logs_db.get_logs(fromBlock, toBlock, address, topics, blockHash)

    def get_block_by_hash(self, block_hash):
        return self._blocks_db.get_block_by_hash(block_hash)

    def get_block_by_height(self, block_height):
        return self._blocks_db.get_block_by_height(block_height)

    def get_tx_by_sol_sign(self, sol_sign):
        tx = self._txs_db.get_tx_by_sol_sign(sol_sign)
        if tx:
            tx.block = self.get_block_by_slot(tx.neon_res.slot)
        return tx

    def get_tx_by_neon_sign(self, neon_sign) -> NeonTxDBInfo:
        tx = self._txs_db.get_tx_by_neon_sign(neon_sign)
        if tx:
            tx.block = self.get_block_by_slot(tx.neon_res.slot)
        return tx

    def del_not_finalized(self, from_slot: int, to_slot: int):
        for d in [self._logs_db, self._blocks_db, self._txs_db]:
            d.del_not_finalized(from_slot=from_slot, to_slot=to_slot)
