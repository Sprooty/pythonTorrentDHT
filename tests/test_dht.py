# -*- coding: utf-8 -*-
import os
import struct
import socket
import pytest
from btpydht.dht import Node, Bucket, RoutingTable, DHT_BASE, DHT
from btpydht.utils import ID, nbit, Scheduler
from btpydht.exceptions import BucketFull, NotFound


class TestNode:
    def test_create_node(self):
        node = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        assert node.id == b'\x01' * 20
        assert node.ip == "1.2.3.4"
        assert node.port == 6881

    def test_invalid_port(self):
        with pytest.raises(ValueError):
            Node(id=b'\x01' * 20, ip="1.2.3.4", port=0)

    def test_invalid_ip_zero(self):
        with pytest.raises(ValueError):
            Node(id=b'\x01' * 20, ip="0.0.0.0", port=6881)

    def test_equality(self):
        n1 = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        n2 = Node(id=b'\x01' * 20, ip="5.6.7.8", port=1234)
        assert n1 == n2  # same id = equal

    def test_inequality(self):
        n1 = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        n2 = Node(id=b'\x02' * 20, ip="1.2.3.4", port=6881)
        assert n1 != n2

    def test_hash(self):
        n1 = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        n2 = Node(id=b'\x01' * 20, ip="5.6.7.8", port=1234)
        assert hash(n1) == hash(n2)

    def test_compact_info(self):
        node = Node(id=b'\xaa' * 20, ip="1.2.3.4", port=6881)
        info = node.compact_info()
        assert len(info) == 26
        (nid, ip, port) = struct.unpack("!20s4sH", info)
        assert nid == b'\xaa' * 20
        assert socket.inet_ntoa(ip) == "1.2.3.4"
        assert port == 6881

    def test_from_compact_info(self):
        original = Node(id=b'\xbb' * 20, ip="10.20.30.40", port=12345)
        info = original.compact_info()
        restored = Node.from_compact_info(info)
        assert restored.id == original.id
        assert restored.ip == original.ip
        assert restored.port == original.port

    def test_from_compact_infos(self):
        n1 = Node(id=b'\x01' * 20, ip="1.2.3.4", port=100)
        n2 = Node(id=b'\x02' * 20, ip="5.6.7.8", port=200)
        infos = n1.compact_info() + n2.compact_info()
        nodes = Node.from_compact_infos(infos)
        assert len(nodes) == 2
        assert nodes[0].id == b'\x01' * 20
        assert nodes[1].id == b'\x02' * 20

    def test_repr(self):
        node = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        assert "1.2.3.4" in repr(node)
        assert "6881" in repr(node)

    def test_good_bad_properties(self):
        import time
        node = Node(
            id=b'\x01' * 20, ip="1.2.3.4", port=6881,
            last_response=int(time.time())
        )
        assert node.good is True
        assert node.bad is False


class TestBucket:
    def _make_dht(self):
        return DHT(bind_port=0)

    def test_create_bucket(self):
        b = Bucket()
        assert len(b) == 0
        assert b.max_size == 8

    def test_own_empty(self):
        b = Bucket()
        assert b.own(b'\x00' * 20) is True

    def test_own_with_prefix(self):
        b = Bucket(id=b'\x80', id_length=1)
        # first bit = 1 → should own ids starting with 1
        assert b.own(b'\x80' + b'\x00' * 19) is True
        assert b.own(b'\x00' * 20) is False

    def test_random_id(self):
        b = Bucket(id=b'\x80', id_length=1)
        rid = b.random_id()
        assert isinstance(rid, ID)
        assert len(rid) == 20

    def test_get_node(self):
        b = Bucket()
        node = Node(id=b'\x01' * 20, ip="1.2.3.4", port=6881)
        b.append(node)
        found = b.get_node(b'\x01' * 20)
        assert found == node

    def test_get_node_not_found(self):
        b = Bucket()
        with pytest.raises(NotFound):
            b.get_node(b'\x01' * 20)


class TestDHT:
    def test_dht_base_not_instantiable(self):
        with pytest.raises(RuntimeError):
            DHT_BASE()

    def test_dht_instantiation(self):
        dht = DHT(bind_port=0)
        assert dht.myid is not None
        assert len(dht.myid) == 20

    def test_dht_custom_id(self):
        custom_id = b'\xab' * 20
        dht = DHT(id=custom_id, bind_port=0)
        assert dht.myid.value == custom_id

    def test_dht_invalid_id(self):
        with pytest.raises(ValueError):
            DHT(id=b'\x00' * 10, bind_port=0)
