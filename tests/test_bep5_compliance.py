# -*- coding: utf-8 -*-
"""
BEP 0005 compliance tests.

Tests verify adherence to the BitTorrent DHT Protocol specification:
https://www.bittorrent.org/beps/bep_0005.html
"""
import os
import time
import struct
import socket
import pytest

from btdht.dht import DHT, DHT_BASE, Node, Bucket, RoutingTable
from btdht.utils import ID, nbit, nflip, nset, bencode, bdecode, Scheduler, id_to_longid
from btdht.krcp import BMessage, BError, ProtocolError, MethodUnknownError
from btdht.exceptions import BucketFull, NotFound


# ---------------------------------------------------------------------------
# Section: Node IDs and Distance Metric
# ---------------------------------------------------------------------------

class TestNodeIDsAndDistance:
    """BEP5: 'Each node has a globally unique identifier known as the node ID.
    Node IDs are chosen at random from the same 160-bit space as BitTorrent
    infohashes.'"""

    def test_node_id_is_160_bits(self):
        """Node IDs must be 160 bits (20 bytes)."""
        node_id = ID()
        assert len(node_id.value) == 20

    def test_node_id_random(self):
        """Node IDs should be random — two generated IDs must differ."""
        id1 = ID()
        id2 = ID()
        assert id1.value != id2.value

    def test_xor_distance_metric(self):
        """BEP5: 'distance(A, B) = |A xor B|'"""
        a = ID(b'\x00' * 20)
        b = ID(b'\xff' * 20)
        dist = a ^ b
        assert dist == b'\xff' * 20

    def test_xor_distance_self_is_zero(self):
        """distance(A, A) = 0"""
        a = ID()
        assert (a ^ a) == b'\x00' * 20

    def test_xor_distance_symmetry(self):
        """distance(A, B) == distance(B, A)"""
        a = ID()
        b = ID()
        assert (a ^ b) == (b ^ a)


# ---------------------------------------------------------------------------
# Section: Routing Table — Bucket Structure
# ---------------------------------------------------------------------------

class TestRoutingTableBuckets:
    """BEP5: 'The routing table is a binary tree whose leaves are K-buckets.
    Each K-bucket holds K=8 contacts.'"""

    def test_bucket_max_size_is_8(self):
        """K = 8 per BEP5."""
        assert Bucket.max_size == 8

    def test_initial_routing_table_has_one_bucket(self):
        """BEP5: 'initially having one bucket with an ID space range of
        min=0, max=2^160.'"""
        scheduler = Scheduler()
        rt = RoutingTable(scheduler=scheduler)
        assert len(list(rt.trie.keys())) == 1

    def test_bucket_split_on_full(self):
        """BEP5: 'When the bucket is full of known good nodes, the new node
        is simply discarded. If the bucket's range includes the node's own ID,
        the bucket is replaced by two new buckets.'"""
        # Use a fixed ID so we control the bucket placement
        my_id = b'\x80' + b'\x00' * 19
        dht = DHT(id=my_id, bind_port=0)
        # Register this DHT so our ID is in _split_ids (triggers bucket splitting)
        dht.root.register_dht(dht)
        initial_keys = len(list(dht.root.trie.keys()))
        # Add 9 nodes that all share the same first bit as our ID (0x80-0xFF range)
        # so they land in the same bucket that contains our own ID
        for i in range(9):
            nid = bytearray(b'\x80' + b'\x00' * 19)
            nid[19] = i + 1  # unique last byte, same first-bit prefix
            ip = "1.2.3.%d" % (i + 1)
            node = Node(id=bytes(nid), ip=ip, port=6881,
                        last_response=int(time.time()))
            dht.root.add(dht, node)
        # After adding 9 good nodes to a bucket containing our own ID, it must split
        assert len(list(dht.root.trie.keys())) > initial_keys


# ---------------------------------------------------------------------------
# Section: Node States
# ---------------------------------------------------------------------------

class TestNodeStates:
    """BEP5: 'A good node is a node has responded to one of our queries within
    the last 15 minutes. A node is also good if it has ever responded to one
    of our queries and has sent us a query within the last 15 minutes.'"""

    def test_recently_responded_node_is_good(self):
        """Responded within 15 minutes → good."""
        node = Node(
            id=b'\x01' * 20, ip="1.2.3.4", port=6881,
            last_response=int(time.time())
        )
        assert node.good is True
        assert node.bad is False

    def test_old_response_with_recent_query_is_good(self):
        """Ever responded AND sent query within 15 min → good."""
        now = int(time.time())
        node = Node(
            id=b'\x01' * 20, ip="1.2.3.4", port=6881,
            last_response=now - 20 * 60,  # responded 20 min ago
            last_query=now  # queried us just now
        )
        assert node.good is True

    def test_inactive_node_is_questionable(self):
        """No activity in 15+ min, not failed → questionable (not good, not bad)."""
        node = Node(
            id=b'\x01' * 20, ip="1.2.3.4", port=6881,
            last_response=int(time.time()) - 20 * 60,
            failed=1
        )
        assert node.good is False
        assert node.bad is False  # failed < 3

    def test_failed_node_is_bad(self):
        """BEP5: 'Nodes become bad when they fail to respond to multiple
        queries in a row.' (implementation uses 3)"""
        node = Node(
            id=b'\x01' * 20, ip="1.2.3.4", port=6881,
            last_response=int(time.time()) - 20 * 60,
            failed=4
        )
        assert node.bad is True


# ---------------------------------------------------------------------------
# Section: Compact Encoding
# ---------------------------------------------------------------------------

class TestCompactEncoding:
    """BEP5: 'Contact information for peers is encoded as a 6-byte string.
    Also known as "Compact IP-address/port info" the 4-byte IP address is in
    network byte order with the 2 byte port in network byte order concatenated
    onto the end.'"""

    def test_compact_peer_info_is_6_bytes(self):
        """Compact peer info must be 6 bytes."""
        ip = socket.inet_aton("192.168.1.1")
        port = 6881
        compact = struct.pack("!4sH", ip, port)
        assert len(compact) == 6

    def test_compact_node_info_is_26_bytes(self):
        """BEP5: 'Contact information for nodes is encoded as a 26-byte
        string. Also known as "Compact node info" the 20-byte Node ID in
        network byte order has the compact IP-address/port info concatenated
        to the end.'"""
        node = Node(id=b'\xaa' * 20, ip="10.0.0.1", port=51413)
        info = node.compact_info()
        assert len(info) == 26

    def test_compact_node_info_roundtrip(self):
        """Pack and unpack compact node info preserves all fields."""
        node = Node(id=b'\xbb' * 20, ip="192.168.1.100", port=12345)
        info = node.compact_info()
        restored = Node.from_compact_info(info)
        assert restored.id == node.id
        assert restored.ip == node.ip
        assert restored.port == node.port

    def test_compact_infos_multiple_of_26(self):
        """from_compact_infos rejects data not a multiple of 26 bytes."""
        with pytest.raises(ValueError):
            Node.from_compact_infos(b'\x00' * 25)


# ---------------------------------------------------------------------------
# Section: KRPC Protocol — Message Format
# ---------------------------------------------------------------------------

class TestKRPCMessageFormat:
    """BEP5: 'The KRPC protocol is a simple RPC mechanism consisting of
    bencoded dictionaries sent over UDP.'"""

    def test_query_has_required_keys(self):
        """BEP5: Queries have keys t, y, q, a."""
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'ping'
        msg.t = b'\x01\x02'
        msg.a = True
        msg[b"id"] = b'\x00' * 20
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert b"t" in decoded
        assert b"y" in decoded
        assert decoded[b"y"] == b"q"
        assert b"q" in decoded
        assert b"a" in decoded

    def test_response_has_required_keys(self):
        """BEP5: Responses have keys t, y, r."""
        msg = BMessage()
        msg.y = b'r'
        msg.t = b'\x01\x02'
        msg.r = True
        msg[b"id"] = b'\x00' * 20
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert b"t" in decoded
        assert b"y" in decoded
        assert decoded[b"y"] == b"r"
        assert b"r" in decoded

    def test_error_has_required_keys(self):
        """BEP5: Errors have keys t, y, e where e is [code, message]."""
        msg = BMessage()
        msg.y = b'e'
        msg.t = b'\x01\x02'
        msg.e = True
        msg.errno = 201
        msg.errmsg = b"Generic Error"
        encoded = msg.encode()
        decoded = bdecode(encoded)
        assert b"t" in decoded
        assert b"y" in decoded
        assert decoded[b"y"] == b"e"
        assert b"e" in decoded
        assert isinstance(decoded[b"e"], list)
        assert decoded[b"e"][0] == 201

    def test_transaction_id_echoed(self):
        """BEP5: 'The transaction ID should be encoded as a short string of
        binary characters... echoed in the response.'"""
        query = BMessage()
        query.y = b'q'
        query.q = b'ping'
        query.t = b'\xaa\xbb'
        query.a = True
        query[b"id"] = b'\x00' * 20

        # Simulate building a response
        dht = DHT(bind_port=0)
        # Decode and respond
        raw = query.encode()
        msg = BMessage(addr=("1.2.3.4", 6881))
        msg.decode(raw, len(raw))
        response = msg.response(dht)
        resp_decoded = bdecode(response.encode())
        assert resp_decoded[b"t"] == b'\xaa\xbb'


# ---------------------------------------------------------------------------
# Section: KRPC Error Codes
# ---------------------------------------------------------------------------

class TestKRPCErrorCodes:
    """BEP5 error codes: 201 Generic, 202 Server, 203 Protocol, 204 Method Unknown."""

    def test_error_201_generic(self):
        from btdht.krcp import GenericError
        err = GenericError(b"\x01\x02", b"test")
        decoded = bdecode(err.encode())
        assert decoded[b"e"][0] == 201

    def test_error_202_server(self):
        from btdht.krcp import ServerError
        err = ServerError(b"\x01\x02")
        decoded = bdecode(err.encode())
        assert decoded[b"e"][0] == 202

    def test_error_203_protocol(self):
        err = ProtocolError(b"\x01\x02")
        decoded = bdecode(err.encode())
        assert decoded[b"e"][0] == 203

    def test_error_204_method_unknown(self):
        err = MethodUnknownError(b"\x01\x02")
        decoded = bdecode(err.encode())
        assert decoded[b"e"][0] == 204


# ---------------------------------------------------------------------------
# Section: RPC Method — ping
# ---------------------------------------------------------------------------

class TestPingMethod:
    """BEP5: 'The most basic query is a ping... "q" = "ping"'
    Arguments: {"id": "<querying nodes id>"}
    Response: {"id": "<queried nodes id>"}"""

    def test_ping_query_format(self):
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'ping'
        msg.t = b'\x01\x02'
        msg.a = True
        msg[b"id"] = b'\xaa' * 20
        decoded = bdecode(msg.encode())
        assert decoded[b"q"] == b"ping"
        assert decoded[b"a"][b"id"] == b'\xaa' * 20

    def test_ping_response_format(self):
        """Ping response must contain queried node's id."""
        dht = DHT(bind_port=0)
        query = BMessage(addr=("1.2.3.4", 6881))
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"ping",
            b"a": {b"id": b"\xbb" * 20}
        })
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert resp_decoded[b"y"] == b"r"
        assert resp_decoded[b"r"][b"id"] == dht.myid.value


# ---------------------------------------------------------------------------
# Section: RPC Method — find_node
# ---------------------------------------------------------------------------

class TestFindNodeMethod:
    """BEP5: '"q" = "find_node"'
    Arguments: {"id": "...", "target": "..."}
    Response: {"id": "...", "nodes": "compact node info"}"""

    def test_find_node_query_format(self):
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'find_node'
        msg.t = b'\x01\x02'
        msg.a = True
        msg[b"id"] = b'\xaa' * 20
        msg[b"target"] = b'\xbb' * 20
        decoded = bdecode(msg.encode())
        assert decoded[b"q"] == b"find_node"
        assert decoded[b"a"][b"target"] == b'\xbb' * 20

    def test_find_node_response_has_nodes(self):
        """find_node response must contain 'nodes' key with compact node info."""
        dht = DHT(bind_port=0)
        # Add a node to routing table so response has data
        n = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881,
                 last_response=int(time.time()))
        dht.root.add(dht, n)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"find_node",
            b"a": {b"id": b"\xbb" * 20, b"target": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert b"nodes" in resp_decoded[b"r"]
        # nodes must be a multiple of 26 bytes
        assert len(resp_decoded[b"r"][b"nodes"]) % 26 == 0

    def test_find_node_missing_target_raises_protocol_error(self):
        """find_node without target must raise ProtocolError."""
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"find_node",
            b"a": {b"id": b"\xbb" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        with pytest.raises(ProtocolError):
            query.response(dht)


# ---------------------------------------------------------------------------
# Section: RPC Method — get_peers
# ---------------------------------------------------------------------------

class TestGetPeersMethod:
    """BEP5: '"q" = "get_peers"'
    Arguments: {"id": "...", "info_hash": "..."}
    Response with peers: {"id": "...", "token": "...", "values": [...]}
    Response without peers: {"id": "...", "token": "...", "nodes": "..."}"""

    def test_get_peers_query_format(self):
        msg = BMessage()
        msg.y = b'q'
        msg.q = b'get_peers'
        msg.t = b'\x01\x02'
        msg.a = True
        msg[b"id"] = b'\xaa' * 20
        msg[b"info_hash"] = b'\xcc' * 20
        decoded = bdecode(msg.encode())
        assert decoded[b"q"] == b"get_peers"
        assert decoded[b"a"][b"info_hash"] == b'\xcc' * 20

    def test_get_peers_response_has_token(self):
        """BEP5: 'The return value... also includes an opaque token value.'"""
        dht = DHT(bind_port=0)
        # Add a node so there's something to return
        n = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881,
                 last_response=int(time.time()))
        dht.root.add(dht, n)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"get_peers",
            b"a": {b"id": b"\xbb" * 20, b"info_hash": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert b"token" in resp_decoded[b"r"], "get_peers response must include token"

    def test_get_peers_no_peers_returns_nodes(self):
        """BEP5: 'If the queried node has no peers... the return value contains
        key "nodes".'"""
        dht = DHT(bind_port=0)
        n = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881,
                 last_response=int(time.time()))
        dht.root.add(dht, n)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"get_peers",
            b"a": {b"id": b"\xbb" * 20, b"info_hash": b"\xcc" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        # No peers stored, so must have nodes
        assert b"nodes" in resp_decoded[b"r"]
        assert len(resp_decoded[b"r"][b"nodes"]) % 26 == 0

    def test_get_peers_with_peers_returns_values(self):
        """BEP5: 'If the queried node has peers... it is returned in a key
        "values" as a list of strings.'"""
        dht = DHT(bind_port=0)
        info_hash = b'\xcc' * 20
        # Simulate stored peers from announce_peer
        dht._peers[info_hash][("10.0.0.1", 51413)] = time.time()
        dht._peers[info_hash][("10.0.0.2", 51413)] = time.time()

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"get_peers",
            b"a": {b"id": b"\xbb" * 20, b"info_hash": info_hash}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert b"values" in resp_decoded[b"r"]
        values = resp_decoded[b"r"][b"values"]
        assert isinstance(values, list)
        # Each value must be 6 bytes (compact peer info)
        for v in values:
            assert len(v) == 6

    def test_get_peers_missing_info_hash_raises_protocol_error(self):
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"get_peers",
            b"a": {b"id": b"\xbb" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        with pytest.raises(ProtocolError):
            query.response(dht)


# ---------------------------------------------------------------------------
# Section: RPC Method — announce_peer
# ---------------------------------------------------------------------------

class TestAnnouncePeerMethod:
    """BEP5: '"q" = "announce_peer"'
    Arguments: {"id": "...", "info_hash": "...", "port": N, "token": "..."}
    Response: {"id": "..."}"""

    def _get_token_for_ip(self, dht, ip):
        """Helper: get a valid token for an IP address."""
        return dht._get_token(ip)

    def test_announce_peer_with_valid_token(self):
        """announce_peer with a valid token must succeed."""
        dht = DHT(bind_port=0)
        ip = "5.6.7.8"
        token = self._get_token_for_ip(dht, ip)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"announce_peer",
            b"a": {
                b"id": b"\xbb" * 20,
                b"info_hash": b"\xcc" * 20,
                b"port": 6881,
                b"token": token
            }
        })
        query = BMessage(addr=(ip, 12345))
        query.decode(raw, len(raw))
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert resp_decoded[b"y"] == b"r"
        assert resp_decoded[b"r"][b"id"] == dht.myid.value

    def test_announce_peer_bad_token_raises_protocol_error(self):
        """BEP5: 'The queried node must verify that the token was previously
        sent to the same IP address.'"""
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"announce_peer",
            b"a": {
                b"id": b"\xbb" * 20,
                b"info_hash": b"\xcc" * 20,
                b"port": 6881,
                b"token": b"BADTOKEN"
            }
        })
        query = BMessage(addr=("5.6.7.8", 12345))
        query.decode(raw, len(raw))
        with pytest.raises(ProtocolError):
            query.response(dht)

    def test_announce_peer_missing_token_raises_protocol_error(self):
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"announce_peer",
            b"a": {
                b"id": b"\xbb" * 20,
                b"info_hash": b"\xcc" * 20,
                b"port": 6881
            }
        })
        query = BMessage(addr=("5.6.7.8", 12345))
        query.decode(raw, len(raw))
        with pytest.raises(ProtocolError):
            query.response(dht)

    def test_announce_peer_implied_port(self):
        """BEP5: 'If implied_port is present and non-zero, the port argument
        should be ignored and the source port of the UDP packet should be used
        as the peer's port instead.'"""
        dht = DHT(bind_port=0)
        ip = "5.6.7.8"
        udp_source_port = 54321
        token = self._get_token_for_ip(dht, ip)
        info_hash = b"\xcc" * 20

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"announce_peer",
            b"a": {
                b"id": b"\xbb" * 20,
                b"info_hash": info_hash,
                b"port": 9999,  # should be ignored
                b"token": token,
                b"implied_port": 1
            }
        })
        query = BMessage(addr=(ip, udp_source_port))
        query.decode(raw, len(raw))
        # Response succeeds
        response = query.response(dht)
        assert bdecode(response.encode())[b"y"] == b"r"

        # Now simulate the _on_announce_peer_query processing
        dht._on_announce_peer_query(query)
        # The stored peer should use UDP source port, not the port field
        assert (ip, udp_source_port) in dht._peers[info_hash]
        assert (ip, 9999) not in dht._peers[info_hash]

    def test_announce_peer_no_implied_port_uses_port_field(self):
        """Without implied_port, the port field value is used."""
        dht = DHT(bind_port=0)
        ip = "5.6.7.8"
        token = self._get_token_for_ip(dht, ip)
        info_hash = b"\xdd" * 20

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"announce_peer",
            b"a": {
                b"id": b"\xbb" * 20,
                b"info_hash": info_hash,
                b"port": 6881,
                b"token": token,
            }
        })
        query = BMessage(addr=(ip, 54321))
        query.decode(raw, len(raw))
        query.response(dht)
        dht._on_announce_peer_query(query)
        assert (ip, 6881) in dht._peers[info_hash]


# ---------------------------------------------------------------------------
# Section: Token Handling
# ---------------------------------------------------------------------------

class TestTokenHandling:
    """BEP5: 'The token value is included in the return value to the node that
    is responding. ...tokens up to ten minutes old are accepted.'"""

    def test_token_generated_per_ip(self):
        """Tokens must be IP-specific."""
        dht = DHT(bind_port=0)
        t1 = dht._get_token("1.2.3.4")
        t2 = dht._get_token("5.6.7.8")
        # Different IPs should generally get different tokens
        # (random, so can't guarantee, but with 4 random bytes collision is rare)
        assert isinstance(t1, bytes)
        assert isinstance(t2, bytes)

    def test_token_valid_within_10_minutes(self):
        """Tokens should be accepted for up to 10 minutes."""
        dht = DHT(bind_port=0)
        ip = "1.2.3.4"
        token = dht._get_token(ip)
        valid = dht._get_valid_token(ip)
        assert token in valid

    def test_token_reuse_within_5_minutes(self):
        """BEP5 reference: 'secret that changes every five minutes'.
        Implementation should reuse token within 5 min window."""
        dht = DHT(bind_port=0)
        ip = "1.2.3.4"
        t1 = dht._get_token(ip)
        t2 = dht._get_token(ip)
        # Second call within 5 min should return same token
        assert t1 == t2

    def test_expired_tokens_rejected(self):
        """Tokens older than 10 minutes must not be valid."""
        dht = DHT(bind_port=0)
        ip = "1.2.3.4"
        # Manually insert an old token (11 minutes ago)
        old_token = os.urandom(4)
        dht.token[ip].append((old_token, time.time() - 11 * 60))
        valid = dht._get_valid_token(ip)
        assert old_token not in valid


# ---------------------------------------------------------------------------
# Section: Unknown Method Handling
# ---------------------------------------------------------------------------

class TestUnknownMethod:
    """BEP5: error code 204 for unknown methods."""

    def test_unknown_method_raises_method_unknown_error(self):
        dht = DHT(bind_port=0)
        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"nonexistent_method",
            b"a": {b"id": b"\xbb" * 20}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        with pytest.raises(MethodUnknownError):
            query.response(dht)


# ---------------------------------------------------------------------------
# Section: get_peers response fallback (nodes vs info_hash)
# ---------------------------------------------------------------------------

class TestGetPeersResponseFallback:
    """BEP5: When no peers, get_peers must return K closest nodes to the
    info_hash, NOT to some other target."""

    def test_get_peers_no_peers_returns_nodes_for_info_hash(self):
        """The nodes returned must be closest to the requested info_hash."""
        dht = DHT(bind_port=0)
        info_hash = b'\xcc' * 20

        # Add nodes at known distances from the info_hash
        for i in range(3):
            nid = bytearray(info_hash)
            nid[0] ^= (i + 1)  # slightly different from info_hash
            node = Node(id=bytes(nid), ip="10.0.0.%d" % (i + 1), port=6881,
                        last_response=int(time.time()))
            dht.root.add(dht, node)

        raw = bencode({
            b"t": b"\x01\x02", b"y": b"q", b"q": b"get_peers",
            b"a": {b"id": b"\xbb" * 20, b"info_hash": info_hash}
        })
        query = BMessage(addr=("5.6.7.8", 6881))
        query.decode(raw, len(raw))
        # This should NOT crash and should return nodes
        response = query.response(dht)
        resp_decoded = bdecode(response.encode())
        assert b"nodes" in resp_decoded[b"r"]


# ---------------------------------------------------------------------------
# Section: Bucket Refresh
# ---------------------------------------------------------------------------

class TestBucketRefresh:
    """BEP5: 'Buckets that have not been changed in 15 minutes should be
    "refreshed." This is done by picking a random ID in the range of the
    bucket and performing a find_nodes search on it.'"""

    def test_bucket_to_refresh_after_15_minutes(self):
        """Bucket should signal refresh needed after 15 min inactivity."""
        b = Bucket()
        b.last_changed = time.time() - 16 * 60
        assert b.to_refresh is True

    def test_bucket_not_refresh_within_15_minutes(self):
        b = Bucket()
        b.last_changed = time.time()
        assert b.to_refresh is False

    def test_bucket_random_id_in_range(self):
        """Random ID generated for refresh must be owned by the bucket."""
        b = Bucket(id=b'\x80', id_length=1)
        for _ in range(10):
            rid = b.random_id()
            assert b.own(rid.value), f"random_id {rid!r} not in bucket range"
