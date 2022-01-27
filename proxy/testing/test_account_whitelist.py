import os
from signal import default_int_handler
import unittest
from unittest import mock
from proxy.common_neon.account_whitelist import AccountWhitelist
from solana.rpc.api import Client as SolanaClient
from solana.account import Account as SolanaAccount
from solana.rpc.commitment import Confirmed
from unittest.mock import Mock, MagicMock, patch, call

class TestAccountWhitelist(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solana = SolanaClient(os.environ['SOLANA_URL'])
        cls.payer = SolanaAccount()
        cls.solana.request_airdrop(cls.payer.public_key(), 1000_000_000_000, Confirmed)
        
        cls.permission_update_int = 10
        cls.testee = AccountWhitelist(cls.solana, cls.payer, cls.permission_update_int)

        mock_allowance_token = Mock()
        mock_allowance_token.get_balance = MagicMock()
        mock_allowance_token.mint_to = MagicMock()
        cls.testee.allowance_token = mock_allowance_token

        mock_denial_token = Mock()
        mock_denial_token.get_balance = MagicMock()
        mock_denial_token.mint_to = MagicMock()
        cls.testee.denial_token = mock_denial_token


    def tearDown(self) -> None:
        self.testee.allowance_token.get_balance.reset_mock()
        self.testee.allowance_token.mint_to.reset_mock()
        self.testee.denial_token.get_balance.reset_mock()
        self.testee.denial_token.mint_to.reset_mock()


    def test_grant_permissions_negative_difference(self):
        """
        Should mint allowance token - negative differenct
        """
        allowance_balance = 100
        denial_balance = 103
        diff = allowance_balance - denial_balance
        min_balance = 3
        expected_mint = min_balance - diff
        ether_address = 'Ethereum-Address'

        self.testee.allowance_token.get_balance.side_effect = [allowance_balance]
        self.testee.denial_token.get_balance.side_effect = [denial_balance]

        self.assertTrue(self.testee.grant_permissions(ether_address, min_balance))

        self.testee.allowance_token.get_balance.assert_called_once_with(ether_address)
        self.testee.denial_token.get_balance.assert_called_once_with(ether_address)
        self.testee.allowance_token.mint_to.assert_called_once_with(expected_mint, ether_address)


    def test_grant_permissions_positive_difference(self):
        """
        Should NOT mint allowance token - positive difference
        """
        allowance_balance = 103
        denial_balance = 100
        min_balance = 1
        ether_address = 'Ethereum-Address'

        self.testee.allowance_token.get_balance.side_effect = [allowance_balance]
        self.testee.denial_token.get_balance.side_effect = [denial_balance]

        self.assertTrue(self.testee.grant_permissions(ether_address, min_balance))

        self.testee.allowance_token.get_balance.assert_called_once_with(ether_address)
        self.testee.denial_token.get_balance.assert_called_once_with(ether_address)
        self.testee.allowance_token.mint_to.assert_not_called()


    def test_deprive_permissions_positive_difference(self):
        """
        Should mint denial token - positive difference
        """
        allowance_balance = 143
        denial_balance = 103
        diff = allowance_balance - denial_balance
        min_balance = 3
        expected_mint = diff - min_balance + 1
        ether_address = 'Ethereum-Address'

        self.testee.allowance_token.get_balance.side_effect = [allowance_balance]
        self.testee.denial_token.get_balance.side_effect = [denial_balance]

        self.assertTrue(self.testee.deprive_permissions(ether_address, min_balance))

        self.testee.allowance_token.get_balance.assert_called_once_with(ether_address)
        self.testee.denial_token.get_balance.assert_called_once_with(ether_address)
        self.testee.denial_token.mint_to.assert_called_once_with(expected_mint, ether_address)


    def test_deprive_permissions_negative_difference(self):
        """
        Should NOT mint denial token - negative difference
        """
        allowance_balance = 14
        denial_balance = 103
        min_balance = 3
        ether_address = 'Ethereum-Address'

        self.testee.allowance_token.get_balance.side_effect = [allowance_balance]
        self.testee.denial_token.get_balance.side_effect = [denial_balance]

        self.assertTrue(self.testee.deprive_permissions(ether_address, min_balance))

        self.testee.allowance_token.get_balance.assert_called_once_with(ether_address)
        self.testee.denial_token.get_balance.assert_called_once_with(ether_address)
        self.testee.denial_token.mint_to.assert_not_called()


    @patch.object(AccountWhitelist, 'get_current_time')
    def test_check_has_permission(self, mock_get_current_time):
        ether_address = 'Ethereum-Address'
        time1 = 123                                     # will cause get_balance call
        time2 = time1 + self.permission_update_int + 2  # will cause get_balance call
        time3 = time2 + self.permission_update_int - 3  # will NOT cause get_balance call
        mock_get_current_time.side_effect = [ time1, time2, time3 ]

        allowance_balance1 = 100
        denial_balance1 = 50
        allowance_balance2 = 100
        denial_balance2 = 150

        self.testee.allowance_token.get_balance.side_effect = [allowance_balance1, allowance_balance2]
        self.testee.denial_token.get_balance.side_effect = [denial_balance1, denial_balance2]

        self.assertTrue(self.testee.has_permission(ether_address, 0))
        self.assertFalse(self.testee.has_permission(ether_address, 0))
        self.assertFalse(self.testee.has_permission(ether_address, 0))

        mock_get_current_time.assert_has_calls([call()] * 3)
        self.testee.allowance_token.get_balance.assert_has_calls([call(ether_address)] * 2)
        self.testee.denial_token.get_balance.assert_has_calls([call(ether_address)] * 2)
        
