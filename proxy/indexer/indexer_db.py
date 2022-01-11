import base58
import logging
import traceback

try:
    from utils import LogDB
    from sql_dict import SQLDict
except ImportError:
    from .utils import LogDB
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
            self.constants['last_block_height'] = 0


    def submit_transaction(self, client, neon_tx, neon_res, used_ixs):
        try:
            block_info = self.get_block_info(client, neon_res.slot)
            if block_info is None:
                logger.critical(f'Unable to submit transaction {neon_tx.sign} because slot {neon_res.slot} not found')
                return
            block_hash, block_number, _ = block_info
            if neon_res.logs:
                for rec in neon_res.logs:
                    rec['transactionHash'] = neon_tx.sign
                    rec['blockHash'] = block_hash
                    rec['blockNumber'] = hex(block_number)
                self.logs_db.push_logs(neon_res.logs)
            self.ethereum_trx[neon_tx.sign] = {
                'eth_trx': neon_tx.rlp_tx,
                'slot': neon_res.slot,
                'blockNumber': hex(block_number),
                'blockHash': block_hash,
                'logs': neon_res.logs,
                'status': neon_res.status,
                'gas_used': neon_res.gas_used,
                'return_value': neon_res.return_value,
                'from_address': neon_tx.addr,
            }

            self.eth_sol_trx[neon_tx.sign] = used_ixs
            for ix in used_ixs:
                self.sol_eth_trx[ix.sign] = {
                    'idx': ix.idx,
                    'eth': neon_tx.sign,
                }
            self.blocks_by_hash[block_hash] = neon_res.slot

            logger.debug(f"{neon_tx.sign} {neon_res.status}")
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            logger.warning(
                f'Got exception while indexing. Type(err): {type(err)}, Exception: {err}, Traceback: {err_tb}')

    def get_block_info(self, client, slot):
        block = self.blocks.get(slot, None)
        if block is None:
            block = client._provider.make_request("getBlock", slot, {"commitment":"confirmed", "transactionDetails":"signatures", "rewards":False})
            if block is None:
                return None
            block = block['result']
            block_hash = '0x' + base58.b58decode(block['blockhash']).hex()
            block_height = block['blockHeight']
            self.blocks[slot] = block
            self.blocks_height_slot[block_height] = slot
            self.blocks_by_hash[block_hash] = slot
        else:
            block_hash = '0x' + base58.b58decode(block['blockhash']).hex()
            block_height = block['blockHeight']
        return block_hash, block_height, block

    def get_last_block_slot(self):
        return self.constants['last_block_slot']

    def get_last_block_height(self):
        return self.constants['last_block_height']

    def set_last_slot_height(self, slot, height):
        self.constants['last_block_slot'] = slot
        self.constants['last_block_height'] = height

    def fill_block_height(self, height, slots):
        for slot in slots:
            self.blocks_height_slot[height] = slot
            height += 1

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
