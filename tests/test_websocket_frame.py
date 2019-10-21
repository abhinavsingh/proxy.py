
class TestWebsocketFrame(unittest.TestCase):

    def test_build_with_mask(self) -> None:
        raw = b'\x81\x85\xc6\ti\x8d\xael\x05\xe1\xa9'
        frame = proxy.WebsocketFrame()
        frame.fin = True
        frame.opcode = proxy.websocketOpcodes.TEXT_FRAME
        frame.masked = True
        frame.mask = b'\xc6\ti\x8d'
        frame.data = b'hello'
        self.assertEqual(frame.build(), raw)

    def test_parse_with_mask(self) -> None:
        raw = b'\x81\x85\xc6\ti\x8d\xael\x05\xe1\xa9'
        frame = proxy.WebsocketFrame()
        frame.parse(raw)
        self.assertEqual(frame.fin, True)
        self.assertEqual(frame.rsv1, False)
        self.assertEqual(frame.rsv2, False)
        self.assertEqual(frame.rsv3, False)
        self.assertEqual(frame.opcode, 0x1)
        self.assertEqual(frame.masked, True)
        assert frame.mask is not None
        self.assertEqual(frame.mask, b'\xc6\ti\x8d')
        self.assertEqual(frame.payload_length, 5)
        self.assertEqual(frame.data, b'hello')
