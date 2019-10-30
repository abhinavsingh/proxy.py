import unittest
import socket
from unittest import mock

from proxy.common.flags import Flags
from proxy.core.acceptor import AcceptorPool


class TestAcceptorPool(unittest.TestCase):

    @mock.patch('proxy.core.acceptor.send_handle')
    @mock.patch('multiprocessing.Pipe')
    @mock.patch('socket.socket')
    @mock.patch('proxy.core.acceptor.Acceptor')
    def test_setup_and_shutdown(
            self,
            mock_worker: mock.Mock,
            mock_socket: mock.Mock,
            mock_pipe: mock.Mock,
            _mock_send_handle: mock.Mock) -> None:
        mock_worker1 = mock.MagicMock()
        mock_worker2 = mock.MagicMock()
        mock_worker.side_effect = [mock_worker1, mock_worker2]

        num_workers = 2
        sock = mock_socket.return_value
        work_klass = mock.MagicMock()
        flags = Flags(num_workers=2)
        acceptor = AcceptorPool(flags=flags, work_klass=work_klass)

        acceptor.setup()

        work_klass.assert_not_called()
        mock_socket.assert_called_with(
            socket.AF_INET6 if acceptor.flags.hostname.version == 6 else socket.AF_INET,
            socket.SOCK_STREAM
        )
        sock.setsockopt.assert_called_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind.assert_called_with(
            (str(acceptor.flags.hostname), acceptor.flags.port))
        sock.listen.assert_called_with(acceptor.flags.backlog)
        sock.setblocking.assert_called_with(False)

        self.assertTrue(mock_pipe.call_count, num_workers)
        self.assertTrue(mock_worker.call_count, num_workers)
        mock_worker1.start.assert_called()
        mock_worker1.join.assert_not_called()
        mock_worker2.start.assert_called()
        mock_worker2.join.assert_not_called()

        sock.close.assert_called()

        acceptor.shutdown()
        mock_worker1.join.assert_called()
        mock_worker2.join.assert_called()
