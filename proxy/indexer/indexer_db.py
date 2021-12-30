import base58
import logging

try:
    from indexer_base import logger, IndexerBase, PARALLEL_REQUESTS
    from utils import check_error, get_trx_results, get_trx_receipts, LogDB, Canceller
    from sql_dict import SQLDict
except ImportError:
    from .indexer_base import logger, IndexerBase, PARALLEL_REQUESTS
    from .utils import check_error, get_trx_results, get_trx_receipts, LogDB, Canceller
    from .sql_dict import SQLDict

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class IndexerDB:
    def __init__(self):
        self.logs_db = LogDB()
        self.blocks = SQLDict(tablename="solana_blocks_by_slot", bin_key=True)
        self.blocks_by_hash = SQLDict(tablename="solana_blocks_by_hash")
        self.blocks_height_slot = SQLDict(tablename="solana_block_height_to_slot", bin_key=True)
        self.ethereum_trx = SQLDict(tablename="ethereum_transactions")
        self.eth_sol_trx = SQLDict(tablename="ethereum_solana_transactions")
        self.sol_eth_trx = SQLDict(tablename="solana_ethereum_transactions")
        self.constants = SQLDict(tablename="constants")
        if 'last_block_slot' not in self.constants:
            self.constants['last_block_slot'] = 0


    def submit_transaction(self, client, eth_trx, eth_signature, from_address, got_result, signatures):
        (logs, status, gas_used, return_value, slot) = got_result
        block_hash, block_number, _ = self.get_block_info(client, slot)
        if logs:
            for rec in logs:
                rec['transactionHash'] = eth_signature
                rec['blockHash'] = block_hash
                rec['blockNumber'] = hex(block_number)
            self.logs_db.push_logs(logs)
        self.ethereum_trx[eth_signature] = {
            'eth_trx': eth_trx,
            'slot': slot,
            'blockNumber': hex(block_number),
            'blockHash': block_hash,
            'logs': logs,
            'status': status,
            'gas_used': gas_used,
            'return_value': return_value,
            'from_address': from_address,
        }
        self.eth_sol_trx[eth_signature] = signatures
        for idx, sig in enumerate(signatures):
            self.sol_eth_trx[sig] = {
                'idx': idx,
                'eth': eth_signature,
            }
        self.blocks_by_hash[block_hash] = slot

        logger.debug(f"{eth_signature} {status}")


    def submit_transaction_part(self, eth_signature, signatures):
        ''' Check if transaction was allready submitted by proxy. '''
        eth_signature = eth_signature
        ethereum_trx = self.ethereum_trx.get(eth_signature, None)
        if ethereum_trx is not None:
            signatures = self.eth_sol_trx.get(eth_signature, [])
            signatures = signatures + signatures
            self.eth_sol_trx[eth_signature] = signatures
            for idx, sig in enumerate(signatures):
                self.sol_eth_trx[sig] = {
                    'idx': idx,
                    'eth': eth_signature,
                }
            return True
        return False

    def get_block_info(self, client, slot):
        block = self.blocks.get(slot, None)
        if block is None:
            block = client._provider.make_request("getBlock", slot, {"commitment":"confirmed", "transactionDetails":"signatures", "rewards":False})['result']
            if block is None:
                return None
            block_hash = '0x' + base58.b58decode(block['blockhash']).hex()
            block_height = block['blockHeight']
            self.blocks_height_slot[block_height] = slot
            self.blocks_by_hash[block_hash] = slot
        else:
            block_hash = '0x' + base58.b58decode(block['blockhash']).hex()
            block_height = block['blockHeight']
        return block_hash, block_height, block

    def get_last_block_slot(self):
        return self.constants['last_block_slot']

    def set_last_block_slot(self, slot):
        self.constants['last_block_slot'] = slot

    def fill_block_height(self, height_slot):
        for height, slot in height_slot.items():
            self.blocks_height_slot[height] = slot

    def get_logs(self, fromBlock, toBlock, address, topics, blockHash):
        return self.logs_db.get_logs(fromBlock, toBlock, address, topics, blockHash)

    def get_slot_by_hash(self, block_hash):
        return self.blocks_by_hash.get(block_hash, None)

    def get_slot_by_number(self, block_number):
        return self.blocks_height_slot.get(block_number, None)

    def get_eth_trx_sig_by_signature(self, signature):
        return self.sol_eth_trx.get(signature, None)

    def get_eth_trx(self, trx_hash):
        return self.ethereum_trx.get(trx_hash, None)
