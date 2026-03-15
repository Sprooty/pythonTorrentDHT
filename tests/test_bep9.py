# -*- coding: utf-8 -*-
"""
Tests for BEP 9 (Extension for Peers to Send Metadata Files)
and BEP 10 (Extension Protocol) implementation.

These tests verify the metadata.py module without requiring a live network
by using mock TCP sockets.
"""
import hashlib
import math
import struct
import socket
import threading
import pytest

from btpydht.utils import bencode, bdecode
from btpydht.metadata import (
    _build_handshake,
    _generate_peer_id,
    _parse_ext_handshake,
    _PROTOCOL_NAME,
    _PIECE_SIZE,
    _MSG_EXTENSION,
    _OUR_UT_METADATA_ID,
    _BEP9_REQUEST,
    _BEP9_DATA,
    _BEP9_REJECT,
    fetch_metadata,
    fetch_metadata_from_peers,
)


# ---------------------------------------------------------------------------
# BEP 10: Extension Protocol
# ---------------------------------------------------------------------------

class TestBEP10Handshake:
    """BEP 10: 'The extension protocol message is sent as message id 20.'"""

    def test_handshake_is_68_bytes(self):
        """BitTorrent handshake must be exactly 68 bytes."""
        hs = _build_handshake(b'\x00' * 20, b'\x01' * 20)
        assert len(hs) == 68

    def test_handshake_starts_with_protocol_name(self):
        """First byte is 19, followed by 'BitTorrent protocol'."""
        hs = _build_handshake(b'\x00' * 20, b'\x01' * 20)
        assert hs[0] == 19
        assert hs[1:20] == b"BitTorrent protocol"

    def test_handshake_extension_bit_set(self):
        """BEP 10: reserved byte[5] bit 0x10 must be set."""
        hs = _build_handshake(b'\x00' * 20, b'\x01' * 20)
        reserved = hs[20:28]
        assert reserved[5] & 0x10, "Extension support bit not set"

    def test_handshake_contains_info_hash_and_peer_id(self):
        info_hash = b'\xaa' * 20
        peer_id = b'\xbb' * 20
        hs = _build_handshake(info_hash, peer_id)
        assert hs[28:48] == info_hash
        assert hs[48:68] == peer_id

    def test_peer_id_format(self):
        """Peer ID starts with -BT0040- and is 20 bytes."""
        pid = _generate_peer_id()
        assert len(pid) == 20
        assert pid.startswith(b"-BT0040-")

    def test_peer_id_random(self):
        """Two generated peer IDs should differ."""
        assert _generate_peer_id() != _generate_peer_id()

    def test_parse_ext_handshake_valid(self):
        """Parse a valid extension handshake response."""
        payload = bencode({
            b"m": {b"ut_metadata": 2},
            b"metadata_size": 32768,
            b"v": b"uTorrent 3.5",
        })
        ut_id, meta_size = _parse_ext_handshake(payload)
        assert ut_id == 2
        assert meta_size == 32768

    def test_parse_ext_handshake_no_ut_metadata(self):
        """Peer without ut_metadata support must raise ValueError."""
        payload = bencode({b"m": {}, b"metadata_size": 100})
        with pytest.raises(ValueError, match="ut_metadata"):
            _parse_ext_handshake(payload)

    def test_parse_ext_handshake_zero_metadata_size(self):
        """Zero metadata_size must raise ValueError."""
        payload = bencode({
            b"m": {b"ut_metadata": 1},
            b"metadata_size": 0,
        })
        with pytest.raises(ValueError, match="metadata_size"):
            _parse_ext_handshake(payload)

    def test_parse_ext_handshake_missing_metadata_size(self):
        """Missing metadata_size must raise ValueError."""
        payload = bencode({b"m": {b"ut_metadata": 1}})
        with pytest.raises(ValueError, match="metadata_size"):
            _parse_ext_handshake(payload)


# ---------------------------------------------------------------------------
# BEP 9: Metadata Extension — mock peer server
# ---------------------------------------------------------------------------

def _make_wire_message(msg_id, payload):
    """Build a length-prefixed BitTorrent wire message."""
    length = 1 + len(payload)
    return struct.pack("!I", length) + bytes([msg_id]) + payload


def _make_ext_message(ext_id, payload):
    """Build a BEP 10 extension message."""
    return _make_wire_message(_MSG_EXTENSION, bytes([ext_id]) + payload)


def _mock_peer(server_sock, info_hash, metadata, send_reject=False, no_ext_support=False):
    """
    Run a mock BitTorrent peer that serves metadata via BEP 9.
    Runs in a thread, accepts one connection.
    """
    conn, _ = server_sock.accept()
    conn.settimeout(5)
    try:
        # Receive client handshake (68 bytes)
        hs = conn.recv(68)
        if len(hs) < 68:
            return

        # Send our handshake back
        reserved = bytearray(8)
        if not no_ext_support:
            reserved[5] = 0x10
        our_hs = (
            bytes([19]) + _PROTOCOL_NAME + bytes(reserved)
            + info_hash + _generate_peer_id()
        )
        conn.sendall(our_hs)

        if no_ext_support:
            conn.close()
            return

        # Receive client's extension handshake (skip the wire framing)
        # Just read and discard it
        length_bytes = conn.recv(4)
        length = struct.unpack("!I", length_bytes)[0]
        conn.recv(length)

        # Send our extension handshake
        our_ut_id = 3  # we tell client our ut_metadata ID is 3
        ext_hs = bencode({
            b"m": {b"ut_metadata": our_ut_id},
            b"metadata_size": len(metadata),
        })
        conn.sendall(_make_ext_message(0, ext_hs))

        # Receive and respond to metadata requests
        num_pieces = math.ceil(len(metadata) / _PIECE_SIZE)

        for _ in range(num_pieces):
            # Read request
            length_bytes = conn.recv(4)
            length = struct.unpack("!I", length_bytes)[0]
            msg_data = conn.recv(length)
            # msg_data[0] = msg_id (20), msg_data[1] = ext_id, msg_data[2:] = payload

            if send_reject:
                reject = bencode({b"msg_type": _BEP9_REJECT, b"piece": 0})
                conn.sendall(_make_ext_message(_OUR_UT_METADATA_ID, reject))
                return

            # Parse the request
            req_dict, _ = __import__('btpydht.utils', fromlist=['bdecode_rest']).bdecode_rest(msg_data[2:])
            piece_idx = req_dict[b"piece"]

            # Build response
            start = piece_idx * _PIECE_SIZE
            end = min(start + _PIECE_SIZE, len(metadata))
            piece_data = metadata[start:end]

            resp_dict = bencode({
                b"msg_type": _BEP9_DATA,
                b"piece": piece_idx,
                b"total_size": len(metadata),
            })
            # Data response: bencoded dict + raw piece data
            conn.sendall(_make_ext_message(
                _OUR_UT_METADATA_ID,
                resp_dict + piece_data
            ))
    except Exception:
        pass
    finally:
        conn.close()


class TestBEP9MetadataFetch:
    """BEP 9: Download torrent metadata from a peer."""

    def _make_metadata(self):
        """Create a valid torrent info dict and its SHA-1 hash."""
        info = {
            b"name": b"test_torrent",
            b"piece length": 262144,
            b"pieces": b'\x00' * 20,
            b"length": 1024,
        }
        raw = bencode(info)
        info_hash = hashlib.sha1(raw).digest()
        return info_hash, raw, info

    def _start_mock_peer(self, info_hash, metadata, **kwargs):
        """Start a mock peer server, return (thread, host, port)."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        _, port = server.getsockname()
        t = threading.Thread(
            target=_mock_peer,
            args=(server, info_hash, metadata),
            kwargs=kwargs,
            daemon=True,
        )
        t.start()
        return t, "127.0.0.1", port, server

    def test_fetch_small_metadata(self):
        """Fetch metadata that fits in a single piece (<16 KiB)."""
        info_hash, metadata, info = self._make_metadata()
        t, ip, port, srv = self._start_mock_peer(info_hash, metadata)

        result = fetch_metadata(info_hash, ip, port, timeout=5.0)
        t.join(timeout=5)
        srv.close()

        assert result is not None
        assert result[b"name"] == b"test_torrent"
        assert result[b"length"] == 1024

    def test_fetch_large_metadata(self):
        """Fetch metadata spanning multiple pieces (>16 KiB)."""
        # Create metadata larger than 16 KiB
        info = {
            b"name": b"big_torrent",
            b"piece length": 262144,
            b"pieces": b'\xaa' * 20 * 100,  # 2000 bytes of pieces
            b"length": 999999,
            b"comment": b"x" * 20000,  # push over 16 KiB
        }
        metadata = bencode(info)
        assert len(metadata) > _PIECE_SIZE
        info_hash = hashlib.sha1(metadata).digest()

        t, ip, port, srv = self._start_mock_peer(info_hash, metadata)

        result = fetch_metadata(info_hash, ip, port, timeout=5.0)
        t.join(timeout=5)
        srv.close()

        assert result is not None
        assert result[b"name"] == b"big_torrent"
        assert result[b"length"] == 999999

    def test_fetch_validates_sha1(self):
        """Metadata with wrong SHA-1 must be rejected."""
        _, metadata, _ = self._make_metadata()
        fake_hash = b'\xff' * 20  # wrong hash

        t, ip, port, srv = self._start_mock_peer(fake_hash, metadata)

        result = fetch_metadata(fake_hash, ip, port, timeout=5.0)
        t.join(timeout=5)
        srv.close()

        assert result is None

    def test_fetch_peer_rejects(self):
        """If peer sends reject, fetch_metadata returns None."""
        info_hash, metadata, _ = self._make_metadata()

        t, ip, port, srv = self._start_mock_peer(info_hash, metadata, send_reject=True)

        result = fetch_metadata(info_hash, ip, port, timeout=5.0)
        t.join(timeout=5)
        srv.close()

        assert result is None

    def test_fetch_no_extension_support(self):
        """Peer without BEP 10 support returns None."""
        info_hash, metadata, _ = self._make_metadata()

        t, ip, port, srv = self._start_mock_peer(info_hash, metadata, no_ext_support=True)

        result = fetch_metadata(info_hash, ip, port, timeout=5.0)
        t.join(timeout=5)
        srv.close()

        assert result is None

    def test_fetch_connection_refused(self):
        """Connection refused returns None gracefully."""
        result = fetch_metadata(b'\x00' * 20, "127.0.0.1", 1, timeout=1.0)
        assert result is None

    def test_fetch_timeout(self):
        """Connection timeout returns None gracefully."""
        # Use a non-routable IP to trigger timeout
        result = fetch_metadata(b'\x00' * 20, "192.0.2.1", 6881, timeout=1.0)
        assert result is None

    def test_fetch_from_peers_tries_multiple(self):
        """fetch_metadata_from_peers tries peers in order, returns first success."""
        info_hash, metadata, _ = self._make_metadata()
        t, ip, port, srv = self._start_mock_peer(info_hash, metadata)

        peers = [
            ("127.0.0.1", 1),  # will fail (connection refused)
            (ip, port),  # will succeed
        ]
        result = fetch_metadata_from_peers(info_hash, peers, timeout=3.0)
        t.join(timeout=5)
        srv.close()

        assert result is not None
        assert result[b"name"] == b"test_torrent"

    def test_fetch_from_peers_all_fail(self):
        """All peers failing returns None."""
        result = fetch_metadata_from_peers(
            b'\x00' * 20,
            [("127.0.0.1", 1), ("127.0.0.1", 2)],
            timeout=1.0,
        )
        assert result is None
