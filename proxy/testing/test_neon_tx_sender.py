import os
import unittest
from solana.rpc.api import Client as SolanaClient
from unittest.mock import Mock

from proxy.common_neon.eth_proto import Trx as EthTrx
from proxy.common_neon.transaction_sender import NeonTxSender
from proxy.common_neon.solana_interactor import SolanaInteractor
from proxy.memdb.memdb import MemDB


class TestNeonTxSender(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solana = SolanaInteractor(os.environ['SOLANA_URL'])

    def setUp(self) -> None:
        trx = EthTrx.fromString(bytearray.fromhex('f8678080843ade68b194f0dafe87532d4373453b2555c644390e1b99e84c8459682f0080820102a00193e1966a82c5597942370980fb78080901ca86eb3c1b25ec600b2760cfcc94a03efcc1169e161f9a148fd4586e0bcf880648ca74075bfa7a9acc8800614fc9ff'))
        self.testee = NeonTxSender(MemDB(self.solana), self.solana, trx, 500)
        self.testee._resource_list.free_resource_info()
        self.testee._validate_pend_tx = Mock()
        self.testee._validate_whitelist = Mock()
        self.testee._validate_tx_count = Mock()
        self.testee._validate_pend_tx.side_effect = [None]
        self.testee._validate_whitelist.side_effect = [None]
        self.testee._validate_tx_count.side_effect = [None]
        self.testee._resource_list._min_operator_balance_to_warn = Mock()
        self.testee._resource_list._min_operator_balance_to_err = Mock()

    def tearDown(self) -> None:
        self.testee._resource_list.free_resource_info()

    # @unittest.skip("a.i.")
    def test_01_validate_execution_when_not_enough_sols(self):
        """
        If the balance value of one of the operator's accounts has become equal to
        the value of the variable MIN_OPERATOR_BALANCE_TO_ERR or less,
        then an error is returned to the client who requested the execution of the transaction
        and an error is written to the log.
        """
        self.testee._resource_list.reset()
        self.testee._resource_list._min_operator_balance_to_warn.side_effect = [1_049_000_000 * 1_000_000_000 * 1_000_000_000 * 2, 1_000_000_000 * 2]
        self.testee._resource_list._min_operator_balance_to_err.side_effect = [1_049_000_000 * 1_000_000_000 * 1_000_000_000, 1_000_000_000]

        with self.assertLogs('neon', level='ERROR') as logs:
            self.testee._validate_execution()
            print('logs.output:', str(logs.output))
            self.assertRegex(str(logs.output), 'ERROR:neon.Proxy:Operator account [A-Za-z0-9]{40,}:[0-9]+ has NOT enough SOLs; balance = [0-9]+; min_operator_balance_to_err = 1049000000000000000000000000')

    # @unittest.skip("a.i.")
    def test_02_validate_warning_when_little_sols(self):
        """
        If the balance value of one of the operator's accounts becomes equal to
        the value of the variable MIN_OPERATOR_BALANCE_TO_WARN or less,
        then a warning is written to the log.:
        """
        self.testee._resource_list.reset()
        self.testee._resource_list._min_operator_balance_to_warn.side_effect = [1_049_000_000 * 1_000_000_000 * 1_000_000_000, 1_000_000_000 * 2]
        self.testee._resource_list._min_operator_balance_to_err.side_effect = [1_049_049_000, 1_000_000_000]

        with self.assertLogs('neon', level='WARNING') as logs:
            # self.testee._resource_list.free_resource_info()
            self.testee._validate_execution()
            print('logs.output:', str(logs.output))
            self.assertRegex(str(logs.output), 'WARNING:neon.Proxy:Operator account [A-Za-z0-9]{40,}:[0-9]+ SOLs are running out; balance = [0-9]+; min_operator_balance_to_warn = 1049000000000000000000000000; min_operator_balance_to_err = 1049049000;')

    # @unittest.skip("a.i.")
    def test_03_validate_execution_when_not_enough_sols_for_all_operator_accounts(self):
        """
        If the balance value of the all operator's accounts has become equal to
        the value of the variable MIN_OPERATOR_BALANCE_TO_ERR or less,
        then an error (RuntimeError('No resources!') )is returned to the client
        who requested the execution of the transaction
        and an error is written to the log.
        """
        self.testee._resource_list.reset()
        self.testee._resource_list._min_operator_balance_to_warn.return_value = 1_049_000_000 * 1_000_000_000 * 1_000_000_000 * 2
        self.testee._resource_list._min_operator_balance_to_err.return_value = 1_049_000_000 * 1_000_000_000 * 1_000_000_000

        with self.assertLogs('neon', level='ERROR') as logs:
            # with self.assertRaises(RuntimeError):
            self.testee._validate_execution()
            print('logs.output:', str(logs.output))
            self.assertRegex(str(logs.output), 'ERROR:neon.Proxy:Operator account [A-Za-z0-9]{40,}:[0-9]+ has NOT enough SOLs; balance = [0-9]+; min_operator_balance_to_err = 1049000000000000000000000000')

