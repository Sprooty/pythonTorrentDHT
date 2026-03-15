# -*- coding: utf-8 -*-
"""
Tests for BEP 51 (DHT Infohash Indexing) implementation.
"""
import time
import pytest

from btdht.dht import DHT, DHT_BASE, Node, RoutingTable
from btdht.krcp import BMessage, ProtocolError
from btdht.utils import ID, bencode, bdecode, Scheduler


class TestBEP51SampleInfohashesQuery:
    """BEP 51: sample_infohashes query format."""

    def test_query_format(self):
        """Query must have q=sample_infohashes with id and target in args."""
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'sample_infohashes'
        msg.t = b'\x01\x02'
        msg.a = True
        msg[b"id"] = b'\xaa' * 20
        msg[b"target"] = b'\xbb' * 20
        decoded = bdecode(msg.encode())
        assert decoded[b"q"] == b"sample_infohashes"
        assert decoded[b"a"][b"id"] == b'\xaa' * 20
        assert decoded[b"a"][b"target"] == b'\xbb' * 20

    def test_node_sample_infohashes_method_exists(self):
        """Node must have a sample_infohashes method."""
        node = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        assert hasattr(node, 'sample_infohashes')


class TestBEP51SampleInfohashesResponse:
    """BEP 51: sample_infohashes response format and handling."""

    def test_response_has_required_fields(self):
        """Response must contain id, interval, nodes, num, samples."""
        dht = DHT(bind_port=0)
        # Add a node so the routing table has something
        n = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881,
                 last_response=int(time.time()))
        dht.root.add(dht, n)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())

        r = resp_decoded[b"r"]
        assert b"id" in r
        assert b"interval" in r
        assert b"nodes" in r
        assert b"num" in r
        assert b"samples" in r

    def test_response_nodes_are_compact(self):
        """Nodes in response must be compact node info (multiple of 26 bytes)."""
        dht = DHT(bind_port=0)
        n = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881,
                 last_response=int(time.time()))
        dht.root.add(dht, n)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())

        nodes = resp_decoded[b"r"][b"nodes"]
        assert len(nodes) % 26 == 0

    def test_response_interval_in_valid_range(self):
        """BEP 51: interval must be 0-21600."""
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())

        interval = resp_decoded[b"r"][b"interval"]
        assert 0 <= interval <= 21600

    def test_response_samples_multiple_of_20(self):
        """BEP 51: samples must be a concatenation of 20-byte hashes."""
        dht = DHT(bind_port=0)
        # Add some peer data so samples is non-empty
        dht._peers[b'\xdd' * 20][("10.0.0.1", 6881)] = time.time()
        dht._peers[b'\xee' * 20][("10.0.0.2", 6881)] = time.time()

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())

        samples = resp_decoded[b"r"][b"samples"]
        assert len(samples) % 20 == 0
        assert len(samples) >= 40  # at least 2 hashes

    def test_response_num_matches_stored_count(self):
        """num field should reflect the number of stored infohashes."""
        dht = DHT(bind_port=0)
        dht._peers[b'\xdd' * 20][("10.0.0.1", 6881)] = time.time()
        dht._peers[b'\xee' * 20][("10.0.0.2", 6881)] = time.time()
        dht._peers[b'\xff' * 20][("10.0.0.3", 6881)] = time.time()

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())

        assert resp_decoded[b"r"][b"num"] >= 3

    def test_response_empty_samples_when_no_peers(self):
        """When no peers stored, samples should be empty."""
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())

        assert resp_decoded[b"r"][b"samples"] == b""
        assert resp_decoded[b"r"][b"num"] == 0

    def test_missing_target_raises_protocol_error(self):
        """sample_infohashes without target must raise ProtocolError."""
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        with pytest.raises(ProtocolError):
            query.response(dht)

    def test_transaction_id_echoed(self):
        """Transaction ID must be echoed in response."""
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\xaa\xbb", b"y": b"q", b"q": b"sample_infohashes",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert resp_decoded[b"t"] == b"\xaa\xbb"


class TestBEP51MessageFields:
    """BEP 51: BMessage support for samples, num, interval fields."""

    def test_set_get_samples(self):
        msg = BMessage()
        msg.r = True
        msg[b"samples"] = b'\xaa' * 40  # two 20-byte hashes
        assert msg[b"samples"] == b'\xaa' * 40
        assert b"samples" in msg

    def test_set_get_num(self):
        msg = BMessage()
        msg.r = True
        msg[b"num"] = 42
        assert msg[b"num"] == 42

    def test_set_get_interval(self):
        msg = BMessage()
        msg.r = True
        msg[b"interval"] = 300
        assert msg[b"interval"] == 300

    def test_fields_in_encoded_output(self):
        """BEP 51 fields must appear in bencoded output."""
        msg = BMessage()
        msg.y = b'r'
        msg.t = b'\x01\x02'
        msg.r = True
        msg[b"id"] = b'\x00' * 20
        msg[b"samples"] = b'\xaa' * 20
        msg[b"num"] = 5
        msg[b"interval"] = 60
        decoded = bdecode(msg.encode())
        r = decoded[b"r"]
        assert r[b"samples"] == b'\xaa' * 20
        assert r[b"num"] == 5
        assert r[b"interval"] == 60

    def test_decode_response_with_bep51_fields(self):
        """Decoding a message with BEP 51 fields should populate them."""
        raw = bencode({
            b"t": b"\x01\x02",
            b"y": b"r",
            b"r": {
                b"id": b'\x00' * 20,
                b"interval": 120,
                b"nodes": b'\x00' * 26,
                b"num": 10,
                b"samples": b'\xbb' * 60,  # 3 hashes
            }
        })
        msg = BMessage(addr=("1.2.3.4", 6881))
        msg.decode(raw, len(raw))
        assert msg[b"interval"] == 120
        assert msg[b"num"] == 10
        assert msg[b"samples"] == b'\xbb' * 60
        assert msg[b"nodes"] == b'\x00' * 26


class TestBEP51DHTProcesing:
    """BEP 51: DHT_BASE correctly routes sample_infohashes messages."""

    def test_dht_has_sample_handlers(self):
        """DHT_BASE must have _on_sample_infohashes_* methods."""
        dht = DHT(bind_port=0)
        assert hasattr(dht, '_on_sample_infohashes_response')
        assert hasattr(dht, '_on_sample_infohashes_query')
        assert hasattr(dht, 'on_sample_infohashes_response')
        assert hasattr(dht, 'on_sample_infohashes_query')

    def test_sample_infohashes_response_adds_nodes(self):
        """_on_sample_infohashes_response should add returned nodes to routing table."""
        dht = DHT(bind_port=0)
        dht.root.register_dht(dht)

        # Build a mock response with a node in it
        node = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        compact = node.compact_info()

        response = BMessage(addr=("5.6.7.8", 6881))
        response.y = b"r"
        response.t = b"\x01\x02"
        response.r = True
        response[b"id"] = b'\x02' * 20
        response[b"nodes"] = compact
        response[b"samples"] = b'\xcc' * 20
        response[b"num"] = 1
        response[b"interval"] = 60

        query = BMessage()
        query.q = b"sample_infohashes"

        initial_nodes = dht.root.stats()[0]
        dht._on_sample_infohashes_response(query, response)
        final_nodes = dht.root.stats()[0]
        assert final_nodes > initial_nodes
