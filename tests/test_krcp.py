# -*- coding: utf-8 -*-
import os
import pytest
from btpydht.krcp import BMessage, BError, GenericError, ServerError, ProtocolError, MethodUnknownError
from btpydht.utils import bencode, bdecode


class TestBMessageConstruction:
    def test_empty_message(self):
        msg = BMessage()
        assert msg.y is None or msg.y == b""

    def test_ping_query(self):
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'ping'
        msg.t = b'\x01\x02'
        msg.a = True
        msg[b"id"] = b'\x00' * 20
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert decoded[b"y"] == b"q"
        assert decoded[b"q"] == b"ping"
        assert decoded[b"t"] == b'\x01\x02'
        assert b"a" in decoded
        assert decoded[b"a"][b"id"] == b'\x00' * 20

    def test_find_node_query(self):
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'find_node'
        msg.t = b'\x03\x04'
        msg.a = True
        msg[b"id"] = b'\x00' * 20
        msg[b"target"] = b'\xff' * 20
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert decoded[b"q"] == b"find_node"
        assert decoded[b"a"][b"target"] == b'\xff' * 20

    def test_get_peers_query(self):
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'get_peers'
        msg.t = b'\x05\x06'
        msg.a = True
        msg[b"id"] = b'\x00' * 20
        msg[b"info_hash"] = b'\xab' * 20
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert decoded[b"q"] == b"get_peers"
        assert decoded[b"a"][b"info_hash"] == b'\xab' * 20

    def test_response_message(self):
        msg = BMessage()
        msg.y = b'r'
        msg.t = b'\x01\x02'
        msg.r = True
        msg[b"id"] = b'\x00' * 20
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert decoded[b"y"] == b"r"
        assert b"r" in decoded
        assert decoded[b"r"][b"id"] == b'\x00' * 20


class TestBMessageDecode:
    def test_decode_ping_query(self):
        raw = bencode({
            b"t": b"\x01\x02",
            b"y": b"q",
            b"q": b"ping",
            b"a": {b"id": b"\xaa" * 20}
        })
        msg = BMessage(addr=("1.2.3.4", 6881))
        msg.decode(raw, len(raw))
        assert msg.y == b"q"
        assert msg.q == b"ping"
        assert msg.t == b"\x01\x02"
        assert msg[b"id"] == b"\xaa" * 20
        assert msg.addr == ("1.2.3.4", 6881)

    def test_decode_response(self):
        raw = bencode({
            b"t": b"\x01\x02",
            b"y": b"r",
            b"r": {b"id": b"\xbb" * 20, b"nodes": b"\x00" * 26}
        })
        msg = BMessage(addr=("1.2.3.4", 6881))
        msg.decode(raw, len(raw))
        assert msg.y == b"r"
        assert msg[b"id"] == b"\xbb" * 20
        assert msg[b"nodes"] == b"\x00" * 26

    def test_decode_error(self):
        raw = bencode({
            b"t": b"\x01\x02",
            b"y": b"e",
            b"e": [201, b"Generic Error"]
        })
        msg = BMessage(addr=("1.2.3.4", 6881))
        msg.decode(raw, len(raw))
        assert msg.y == b"e"
        assert msg.errno == 201
        assert msg.errmsg == b"Generic Error"

    def test_roundtrip(self):
        msg1 = BMessage()
        msg1.y = b'q'
        msg1.q = b'ping'
        msg1.t = b'\xaa\xbb'
        msg1.a = True
        msg1[b"id"] = b'\xcc' * 20
        encoded = msg1.encode()

        msg2 = BMessage(addr=("1.2.3.4", 6881))
        msg2.decode(encoded, len(encoded))
        assert msg2.y == b"q"
        assert msg2.q == b"ping"
        assert msg2.t == b'\xaa\xbb'
        assert msg2[b"id"] == b'\xcc' * 20


class TestBMessageDictInterface:
    def test_setitem_getitem(self):
        msg = BMessage()
        msg.a = True
        msg[b"id"] = b'\x00' * 20
        assert msg[b"id"] == b'\x00' * 20

    def test_contains(self):
        msg = BMessage()
        msg.a = True
        msg[b"id"] = b'\x00' * 20
        assert b"id" in msg

    def test_get_default(self):
        msg = BMessage()
        assert msg.get(b"nonexistent", b"default") == b"default"


class TestBErrors:
    def test_generic_error(self):
        err = GenericError(b"\x01\x02", b"test error")
        assert err.e == [201, b"test error"]
        encoded = err.encode()
        decoded = bdecode(encoded)
        assert decoded[b"y"] == b"e"
        assert decoded[b"e"] == [201, b"test error"]

    def test_server_error(self):
        err = ServerError(b"\x01\x02")
        assert err.e[0] == 202

    def test_protocol_error(self):
        err = ProtocolError(b"\x01\x02")
        assert err.e[0] == 203

    def test_method_unknown_error(self):
        err = MethodUnknownError(b"\x01\x02")
        assert err.e[0] == 204

    def test_berror_requires_t(self):
        with pytest.raises(ValueError):
            BError(None, [201, b"test"])
