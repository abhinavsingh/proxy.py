from typing import Any, Tuple
from abc import ABC, abstractmethod

import asyncio
from asyncio import StreamReader, StreamWriter
import socket
import pickle
import struct
from logged_groups import logged_group


class IPickableDataServerUser(ABC):

    @abstractmethod
    async def on_data_received(self, data: Any) -> Any:
        """Gets neon_tx_data from the neon rpc api service worker"""


@logged_group("neon.Network")
class PickableDataServer(ABC):

    def __init__(self, *, user: IPickableDataServerUser):
        self._user = user
        asyncio.get_event_loop().create_task(self.run_server())

    @abstractmethod
    async def run_server(self):
        assert False

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        while True:
            try:
                self.debug("Got incoming connection. Waiting for pickable data")
                data = await self._recv_pickable_data(reader)
                result = await self._user.on_data_received(data)
                self.debug(f"Encode pickable result_data: {result}")
                result_data = encode_pickable(result, self)
                self.debug(f"Send result_data: {len(result_data)}, bytes: {result_data.hex()}")
                writer.write(result_data)
                await writer.drain()
            except ConnectionResetError as err:
                self.warning(f"Connection reset error: {err}")
                break
            except asyncio.exceptions.IncompleteReadError as err:
                self.error(f"Incomplete read error: {err}")
                break
            except Exception as err:
                self.error(f"Failed to receive data err: {err}")
                break

    async def _recv_pickable_data(self, reader: StreamReader):
        len_packed: bytes = await read_data_async(self, reader, 4)
        payload_len = struct.unpack("!I", len_packed)[0]
        self.debug(f"Got payload len_packed: {len_packed.hex()}, that is: {payload_len}")
        payload = await read_data_async(self, reader, payload_len)
        data = pickle.loads(payload)
        self.debug(f"Loaded pickable of type: {type(data)}")
        return data


@logged_group("neon.MemPool")
class AddrPickableDataSrv(PickableDataServer):

    def __init__(self, *, user: IPickableDataServerUser, address: Tuple[str, int]):
        self._address = address
        PickableDataServer.__init__(self, user=user)

    async def run_server(self):
        host, port = self._address
        self.info(f"Listen port: {port} on: {host}")
        await asyncio.start_server(self.handle_client, host, port)


@logged_group("neon.Network")
class PipePickableDataSrv(PickableDataServer):

    def __init__(self, *, user: IPickableDataServerUser, srv_sock: socket.socket):
        self._srv_sock = srv_sock
        PickableDataServer.__init__(self, user=user)

    async def run_server(self):
        reader, writer = await asyncio.streams.open_connection(sock=self._srv_sock)
        await self.handle_client(reader, writer)


class PickableDataClient:

    def __init__(self):
        self._client_sock: socket.socket = None
        self._reader: StreamReader = None
        self._writer: StreamWriter = None

    def _set_client_sock(self, client_sock: socket.socket):
        self._client_sock = client_sock

    async def async_init(self):
        self.info("Async init pickable data client")
        reader, writer = await asyncio.open_connection(sock=self._client_sock)
        self._reader = reader
        self._writer = writer

    def send_data(self, pickable_object: Any):
        try:
            payload: bytes = encode_pickable(pickable_object, self)
            self.debug(f"Send object of type: {type(pickable_object)}, payload: {len(payload)}, bytes: 0x{payload[:15].hex()}")
            self._client_sock.sendall(payload)
        except BaseException as err:
            self.error(f"Failed to send client data: {err}")
            raise
        try:
            self.debug(f"Waiting for answer")
            len_packed: bytes = read_data_sync(self, self._client_sock, 4)
            data_len = struct.unpack("!I", len_packed)[0]
            self.debug(f"Got len_packed bytes: {len_packed.hex()}, that is: {data_len} - bytes to receive")

            data = read_data_sync(self, self._client_sock, data_len)
            self.debug(f"Got data: {len(data)}. Load pickled object")
            result = pickle.loads(data)
            self.debug(f"Got result: {result}")
            return result
        except BaseException as err:
            self.error(f"Failed to receive answer data: {err}")
            raise

    async def send_data_async(self, pickable_object):

        try:
            self.debug(f"Send pickable_object of type: {type(pickable_object)}")
            payload = encode_pickable(pickable_object, self)
            self.debug(f"Payload: {len(payload)}, bytes: {payload[:15].hex()}")
            self._writer.write(payload)
            await self._writer.drain()

        except BaseException as err:
            self.error(f"Failed to send client data: {err}")
            raise

        try:
            self.debug(f"Waiting for answer")
            len_packed: bytes = await read_data_async(self, self._reader, 4)
            data_len = struct.unpack("!I", len_packed)[0]
            data = await read_data_async(self, self._reader, data_len)
            self.debug(f"Got data: {len(data)}. Load pickled object")
            result = pickle.loads(data)
            self.debug(f"Got result: {result}")
            return result

        except BaseException as err:
            self.error(f"Failed to receive answer data: {err}")
            raise


@logged_group("neon.Network")
class PipePickableDataClient(PickableDataClient):

    def __init__(self, client_sock: socket.socket):
        PickableDataClient.__init__(self)
        self._set_client_sock(client_sock=client_sock)


@logged_group("neon.Network")
class AddrPickableDataClient(PickableDataClient):

    def __init__(self, addr: Tuple[str, int]):
        PickableDataClient.__init__(self)
        host, port = addr
        client_sock = socket.create_connection((host, port))
        self._set_client_sock(client_sock=client_sock)


def encode_pickable(object, logger) -> bytes:
    data = pickle.dumps(object)
    len_data = struct.pack("!I", len(data))
    logger.debug(f"Len data: {len(len_data)} - bytes, data: {len(data)} - bytes")
    return len_data + data


async def read_data_async(self, reader: StreamReader, data_len: int) -> bytes:
    data = b''
    while len(data) < data_len:
        to_be_read = data_len - len(data)
        self.debug(f"Reading data: {to_be_read} of: {data_len} - bytes")
        chunk = await reader.read(to_be_read)
        if not chunk:
            raise EOFError(f"Failed to read chunk of data: {data_len}")
        self.debug(f"Got chunk of data: {len(chunk)}")
        data += chunk
    return data


def read_data_sync(self, socket: socket.socket, data_len) -> bytes:
    data = b''
    while len(data) < data_len:
        to_be_read = data_len - len(data)
        self.debug(f"Reading data: {to_be_read} of: {data_len} - bytes")
        chunk: bytes = socket.recv(to_be_read)
        self.debug(f"Got chunk of data: {len(chunk)}")
        data += chunk
    return data
