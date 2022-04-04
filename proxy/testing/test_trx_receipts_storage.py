from unittest import TestCase
from proxy.indexer.trx_receipts_storage import TxReceiptsStorage
from random import randint
from base58 import b58encode


class TestTxReceiptsStorage(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tx_receipts_storage = TxReceiptsStorage('test_storage')

    def create_signature(self):
        signature = b''
        for i in range(0, 5):
            signature += randint(0, 255).to_bytes(1, byteorder='big')
        return b58encode(signature).decode("utf-8")

    def create_slot_sig(self, max_slot):
        slot = randint(0, max_slot)
        return (slot, self.create_signature())

    def test_data_consistency(self):
        """
        Test that data put into container is stored there
        """
        self.tx_receipts_storage.clear()
        self.assertEqual(self.tx_receipts_storage.size(), 0)
        self.assertEqual(self.tx_receipts_storage.max_known_tx(), (0, None))

        max_slot = 10
        num_items = 100
        expected_items = []
        for idx in range(0, num_items):
            slot, signature = self.create_slot_sig(max_slot)
            tx = {'slot': slot, 'signature': signature}
            self.tx_receipts_storage.add_tx(slot, idx, signature, tx)
            expected_items.append((slot, idx, signature, tx))

        self.assertEqual(self.tx_receipts_storage.max_known_tx()[0], max_slot)
        self.assertEqual(self.tx_receipts_storage.size(), num_items)
        for item in expected_items:
            self.assertTrue(self.tx_receipts_storage.contains(item[0], item[2]))

    def test_query(self):
        """
        Test get_txs method works as expected
        """
        self.tx_receipts_storage.clear()
        self.assertEqual(self.tx_receipts_storage.size(), 0)

        max_slot = 50
        num_items = 100
        expected_items = []
        for idx in range(0, num_items):
            slot, signature = self.create_slot_sig(max_slot)
            trx = {'slot': slot, 'signature': signature}
            self.tx_receipts_storage.add_tx(slot, idx, signature, trx)
            expected_items.append((slot, idx, signature, trx))

        start_slot = randint(0, 50)

        # query in ascending order
        retrieved_txs = [item for item in self.tx_receipts_storage.get_txs(start_slot)]
        self.assertGreaterEqual(retrieved_txs[0][0], start_slot)
        self.assertLessEqual(retrieved_txs[-1][0], max_slot)
