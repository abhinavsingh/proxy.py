from unittest import TestCase
from proxy.indexer.trx_receipts_storage import TrxReceiptsStorage
from random import randint
from base58 import b58encode


class TestTrxReceiptsStorage(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print("\n\nhttps://github.com/neonlabsorg/proxy-model.py/issues/421")
        cls.testee = TrxReceiptsStorage('test_storage')

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
        self.testee.clear()
        self.assertEqual(self.testee.size(), 0)
        self.assertEqual(self.testee.max_known_trx(), (0, None))

        max_slot = 10
        num_items = 100
        expected_items = []
        for _ in range(0, num_items):
            slot, signature = self.create_slot_sig(max_slot)
            trx = { 'slot': slot, 'signature': signature }
            self.testee.add_trx(slot, signature, trx)
            expected_items.append((slot, signature, trx))

        self.assertEqual(self.testee.max_known_trx()[0], max_slot)
        self.assertEqual(self.testee.size(), num_items)
        for item in expected_items:
            self.assertTrue(self.testee.contains(item[0], item[1]))

    def test_query(self):
        """
        Test get_trxs method workds as expected
        """
        self.testee.clear()
        self.assertEqual(self.testee.size(), 0)

        max_slot = 50
        num_items = 100
        expected_items = []
        for _ in range(0, num_items):
            slot, signature = self.create_slot_sig(max_slot)
            trx = { 'slot': slot, 'signature': signature }
            self.testee.add_trx(slot, signature, trx)
            expected_items.append((slot, signature, trx))

        start_slot = randint(0, 50)

        # query in ascending order
        retrieved_trxs = [item for item in self.testee.get_trxs(start_slot, False)]
        self.assertGreaterEqual(retrieved_trxs[0][0], start_slot)
        self.assertLessEqual(retrieved_trxs[-1][0], max_slot)

        # query in descending order
        retrieved_trxs = [item for item in self.testee.get_trxs(start_slot, True)]
        self.assertLessEqual(retrieved_trxs[0][0], max_slot)
        self.assertGreaterEqual(retrieved_trxs[-1][0], start_slot)