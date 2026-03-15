# -*- coding: utf-8 -*-
import os
import pytest
from btdht.utils import (
    ID, bencode, bdecode, bdecode_rest,
    nbit, nflip, nset, enumerate_ids, id_to_longid,
    PollableQueue,
)
from btdht.exceptions import BcodeError


class TestBencode:
    def test_encode_int(self):
        assert bencode(42) == b"i42e"
        assert bencode(0) == b"i0e"
        assert bencode(-1) == b"i-1e"

    def test_encode_bytes(self):
        assert bencode(b"spam") == b"4:spam"
        assert bencode(b"") == b"0:"

    def test_encode_list(self):
        assert bencode([b"spam", b"eggs"]) == b"l4:spam4:eggse"
        assert bencode([]) == b"le"

    def test_encode_dict(self):
        assert bencode({b"cow": b"moo", b"spam": b"eggs"}) == b"d3:cow3:moo4:spam4:eggse"
        assert bencode({}) == b"de"

    def test_encode_nested(self):
        assert bencode({b"list": [1, 2, 3]}) == b"d4:listli1ei2ei3eee"

    def test_encode_invalid_type(self):
        with pytest.raises(EnvironmentError):
            bencode(object())


class TestBdecode:
    def test_decode_int(self):
        assert bdecode(b"i42e") == 42
        assert bdecode(b"i0e") == 0
        assert bdecode(b"i-1e") == -1

    def test_decode_string(self):
        assert bdecode(b"4:spam") == b"spam"
        assert bdecode(b"0:") == b""

    def test_decode_list(self):
        assert bdecode(b"l4:spam4:eggse") == [b"spam", b"eggs"]
        assert bdecode(b"le") == []

    def test_decode_dict(self):
        result = bdecode(b"d3:cow3:moo4:spam4:eggse")
        assert result == {b"cow": b"moo", b"spam": b"eggs"}
        assert bdecode(b"de") == {}

    def test_decode_nested(self):
        result = bdecode(b"d4:listli1ei2ei3eee")
        assert result == {b"list": [1, 2, 3]}

    def test_roundtrip(self):
        original = {b"t": b"\x01\x02", b"y": b"q", b"q": b"ping", b"a": {b"id": b"x" * 20}}
        assert bdecode(bencode(original)) == original

    def test_decode_rest(self):
        obj, rest = bdecode_rest(b"4:spamextra")
        assert obj == b"spam"
        assert rest == b"extra"

    def test_decode_invalid(self):
        with pytest.raises(BcodeError):
            bdecode(b"z")


class TestID:
    def test_random_generation(self):
        id1 = ID()
        id2 = ID()
        assert len(id1.value) == 20
        assert len(id2.value) == 20
        assert id1 != id2

    def test_from_bytes(self):
        raw = os.urandom(20)
        id_obj = ID(raw)
        assert id_obj.value == raw

    def test_from_id(self):
        id1 = ID()
        id2 = ID(id1)
        assert id1 == id2

    def test_xor(self):
        id1 = ID(b"\x00" * 20)
        id2 = ID(b"\xff" * 20)
        result = id1 ^ id2
        assert result == b"\xff" * 20

    def test_xor_with_bytes(self):
        id1 = ID(b"\xff" * 20)
        result = id1 ^ b"\xff" * 20
        assert result == b"\x00" * 20

    def test_hash(self):
        raw = os.urandom(20)
        id1 = ID(raw)
        id2 = ID(raw)
        assert hash(id1) == hash(id2)
        assert id1 == id2

    def test_equality(self):
        raw = os.urandom(20)
        assert ID(raw) == ID(raw)
        assert not (ID(raw) == ID())

    def test_ordering(self):
        id1 = ID(b"\x00" * 20)
        id2 = ID(b"\xff" * 20)
        assert id1 < id2

    def test_repr(self):
        id_obj = ID(b"\xab\xcd" + b"\x00" * 18)
        assert id_obj.__repr__() == "abcd" + "00" * 18

    def test_len(self):
        assert len(ID()) == 20

    def test_startswith(self):
        id_obj = ID(b"\xab\xcd" + b"\x00" * 18)
        assert id_obj.startswith(b"\xab")

    def test_getitem(self):
        id_obj = ID(b"\x01\x02" + b"\x00" * 18)
        assert id_obj[0] == 1
        assert id_obj[1] == 2


class TestBitOps:
    def test_nbit(self):
        # 0b10000000 = 0x80
        assert nbit(b"\x80", 0) == 1
        assert nbit(b"\x80", 1) == 0
        # 0b01000000 = 0x40
        assert nbit(b"\x40", 0) == 0
        assert nbit(b"\x40", 1) == 1

    def test_nflip(self):
        result = nflip(b"\x00", 0)
        assert result == b"\x80"
        result = nflip(b"\x80", 0)
        assert result == b"\x00"

    def test_nset(self):
        result = nset(b"\x00", 0, 1)
        assert result == b"\x80"
        result = nset(b"\x80", 0, 0)
        assert result == b"\x00"

    def test_nset_invalid(self):
        with pytest.raises(ValueError):
            nset(b"\x00", 0, 2)

    def test_enumerate_ids(self):
        base = b"\x00" * 20
        ids = enumerate_ids(2, base)
        assert len(ids) == 4


class TestIdToLongid:
    def test_zero(self):
        result = id_to_longid(b"\x00", 1)
        assert result == "00000000"

    def test_ff(self):
        result = id_to_longid(b"\xff", 1)
        assert result == "11111111"

    def test_roundtrip_length(self):
        result = id_to_longid(b"\x00" * 20, 20)
        assert len(result) == 160


class TestPollableQueue:
    def test_put_get(self):
        q = PollableQueue()
        q.put("item")
        assert q.get_nowait() == "item"

    def test_has_sock(self):
        q = PollableQueue()
        assert q.sock is not None
