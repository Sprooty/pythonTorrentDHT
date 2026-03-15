# -*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
BEP 9 / BEP 10 implementation — download torrent metadata from a peer.

Connects to a BitTorrent peer via TCP, performs the BEP 10 extension
handshake, then requests and reassembles the info-dict metadata via BEP 9.
"""

from __future__ import annotations

import hashlib
import math
import os
import socket
import struct

from .utils import bencode, bdecode_rest

# ── constants ────────────────────────────────────────────────────────────────

_PROTOCOL_NAME = b"BitTorrent protocol"
_PIECE_SIZE = 16384  # 16 KiB per BEP 9

# Extension message id used inside the BitTorrent wire protocol.
_MSG_EXTENSION = 20

# BEP 9 message types
_BEP9_REQUEST = 0
_BEP9_DATA = 1
_BEP9_REJECT = 2

# The extension id we advertise for ut_metadata.
_OUR_UT_METADATA_ID = 1


# ── low-level helpers ────────────────────────────────────────────────────────

def _generate_peer_id() -> bytes:
    """Return a random 20-byte peer id starting with -BT0040-."""
    return b"-BT0040-" + os.urandom(12)


def _build_handshake(info_hash: bytes, peer_id: bytes) -> bytes:
    """Build the 68-byte BitTorrent handshake message."""
    reserved = bytearray(8)
    reserved[5] = reserved[5] | 0x10  # BEP 10 extension support
    return (
        bytes([19])
        + _PROTOCOL_NAME
        + bytes(reserved)
        + info_hash
        + peer_id
    )


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, or raise ``ConnectionError``."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


def _recv_handshake(sock: socket.socket) -> tuple[bytes, bytes, bool]:
    """
    Receive and parse the 68-byte BitTorrent handshake.

    Returns
    -------
    info_hash : bytes
        The 20-byte info hash the peer sent.
    peer_id : bytes
        The 20-byte peer id.
    supports_extension : bool
        Whether the peer advertises BEP 10 support.
    """
    pstrlen_bytes = _recv_exact(sock, 1)
    pstrlen = pstrlen_bytes[0]
    pstr = _recv_exact(sock, pstrlen)
    if pstr != _PROTOCOL_NAME:
        raise ValueError("Unexpected protocol string")
    reserved = _recv_exact(sock, 8)
    info_hash = _recv_exact(sock, 20)
    peer_id = _recv_exact(sock, 20)
    supports_extension = bool(reserved[5] & 0x10)
    return info_hash, peer_id, supports_extension


def _send_message(sock: socket.socket, message_id: int, payload: bytes) -> None:
    """Send a length-prefixed BitTorrent wire message."""
    length = 1 + len(payload)
    sock.sendall(struct.pack("!I", length) + bytes([message_id]) + payload)


def _send_extension_message(sock: socket.socket, ext_id: int, payload: bytes) -> None:
    """Send a BEP 10 extension message (message_id=20)."""
    _send_message(sock, _MSG_EXTENSION, bytes([ext_id]) + payload)


def _recv_message(sock: socket.socket) -> tuple[int, bytes] | None:
    """
    Read one length-prefixed wire message.

    Returns ``None`` for keep-alive (length == 0), otherwise
    ``(message_id, payload)``.
    """
    length_bytes = _recv_exact(sock, 4)
    length = struct.unpack("!I", length_bytes)[0]
    if length == 0:
        return None  # keep-alive
    data = _recv_exact(sock, length)
    return data[0], data[1:]


def _send_ext_handshake(sock: socket.socket) -> None:
    """Send our BEP 10 extension handshake."""
    handshake_dict = {
        b"m": {b"ut_metadata": _OUR_UT_METADATA_ID},
        b"metadata_size": 0,
    }
    _send_extension_message(sock, 0, bencode(handshake_dict))


def _parse_ext_handshake(payload: bytes) -> tuple[int, int]:
    """
    Parse the peer's extension handshake payload.

    Returns
    -------
    ut_metadata_id : int
        The peer's message id for ut_metadata.
    metadata_size : int
        Total metadata size in bytes.

    Raises
    ------
    ValueError
        If the peer does not support ut_metadata or metadata_size is missing/zero.
    """
    d, _ = bdecode_rest(payload)
    m = d.get(b"m", {})
    ut_metadata_id = m.get(b"ut_metadata")
    if ut_metadata_id is None:
        raise ValueError("Peer does not support ut_metadata")
    metadata_size = d.get(b"metadata_size", 0)
    if not metadata_size:
        raise ValueError("Peer reports zero metadata_size")
    return int(ut_metadata_id), int(metadata_size)


# ── public API ───────────────────────────────────────────────────────────────

def fetch_metadata(
    info_hash: bytes,
    peer_ip: str,
    peer_port: int,
    timeout: float = 15.0,
) -> dict | None:
    """
    Connect to a peer and download torrent metadata via BEP 9.

    Args:
        info_hash: 20-byte info hash.
        peer_ip: Peer IP address.
        peer_port: Peer TCP port.
        timeout: Connection/read timeout in seconds.

    Returns:
        The decoded info dict (contains ``b'name'``, ``b'piece length'``,
        ``b'pieces'``, optionally ``b'files'`` for multi-file or ``b'length'``
        for single-file), or ``None`` if metadata could not be fetched.
    """
    peer_id = _generate_peer_id()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((peer_ip, peer_port))

        # ── BitTorrent handshake ─────────────────────────────────────────
        sock.sendall(_build_handshake(info_hash, peer_id))
        _, _, supports_ext = _recv_handshake(sock)
        if not supports_ext:
            return None

        # ── BEP 10 extension handshake ───────────────────────────────────
        _send_ext_handshake(sock)

        # Wait for the peer's extension handshake. Skip any non-extension
        # messages (bitfield, have, etc.) that may arrive first.
        peer_ut_metadata_id: int | None = None
        metadata_size: int = 0

        while True:
            msg = _recv_message(sock)
            if msg is None:
                continue  # keep-alive
            msg_id, payload = msg
            if msg_id == _MSG_EXTENSION and len(payload) >= 1:
                ext_id = payload[0]
                if ext_id == 0:
                    # Extension handshake response
                    try:
                        peer_ut_metadata_id, metadata_size = _parse_ext_handshake(
                            payload[1:]
                        )
                    except ValueError:
                        return None
                    break
            # Otherwise skip the message and keep reading.

        if peer_ut_metadata_id is None or metadata_size <= 0:
            return None

        # ── BEP 9 metadata download ─────────────────────────────────────
        num_pieces = math.ceil(metadata_size / _PIECE_SIZE)
        pieces: dict[int, bytes] = {}

        # Request all pieces upfront.
        for piece_idx in range(num_pieces):
            request_payload = bencode(
                {b"msg_type": _BEP9_REQUEST, b"piece": piece_idx}
            )
            _send_extension_message(sock, peer_ut_metadata_id, request_payload)

        # Collect responses.
        while len(pieces) < num_pieces:
            msg = _recv_message(sock)
            if msg is None:
                continue  # keep-alive
            msg_id, payload = msg
            if msg_id != _MSG_EXTENSION:
                continue  # skip non-extension messages
            if len(payload) < 2:
                continue
            ext_id = payload[0]
            if ext_id != _OUR_UT_METADATA_ID:
                # Could be another extension message; skip.
                if ext_id == 0:
                    # Another extension handshake (some peers re-send); skip.
                    pass
                continue

            # Parse the bencoded dict; everything after it is piece data.
            try:
                d, piece_data = bdecode_rest(payload[1:])
            except Exception:
                return None

            msg_type = d.get(b"msg_type")
            piece_idx = d.get(b"piece")

            if msg_type == _BEP9_REJECT:
                return None
            if msg_type != _BEP9_DATA or piece_idx is None:
                continue

            pieces[piece_idx] = piece_data

        # ── Reassemble and validate ──────────────────────────────────────
        metadata = b"".join(pieces[i] for i in range(num_pieces))

        if len(metadata) != metadata_size:
            return None

        if hashlib.sha1(metadata).digest() != info_hash:
            return None

        info_dict, _ = bdecode_rest(metadata)
        return info_dict

    except (
        OSError,
        ConnectionError,
        socket.timeout,
        TimeoutError,
        ValueError,
        KeyError,
        IndexError,
        struct.error,
    ):
        return None
    finally:
        sock.close()


def fetch_metadata_from_peers(
    info_hash: bytes,
    peers: list[tuple[str, int]],
    timeout: float = 10.0,
) -> dict | None:
    """
    Try multiple peers and return the first successful metadata fetch.

    Args:
        info_hash: 20-byte info hash.
        peers: List of ``(ip, port)`` tuples.
        timeout: Per-peer connection/read timeout in seconds.

    Returns:
        The decoded info dict, or ``None`` if no peer could provide the metadata.
    """
    for peer_ip, peer_port in peers:
        result = fetch_metadata(info_hash, peer_ip, peer_port, timeout=timeout)
        if result is not None:
            return result
    return None
