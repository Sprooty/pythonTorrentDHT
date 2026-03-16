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
BEP 9 / BEP 10 / BEP 11 implementation — download torrent metadata from a peer.

Connects to a BitTorrent peer via TCP, performs the BEP 10 extension
handshake, then requests and reassembles the info-dict metadata via BEP 9.
Optionally collects PEX (BEP 11) peer/seed counts from the same connection.
"""

from __future__ import annotations

import hashlib
import math
import os
import socket
import struct
import time

from .utils import bencode, bdecode_rest

# ── constants ────────────────────────────────────────────────────────────────

_PROTOCOL_NAME = b"BitTorrent protocol"
_PIECE_SIZE = 16384  # 16 KiB per BEP 9
_BLOCK_SIZE = 16384  # 16 KiB standard block request size

# Extension message id used inside the BitTorrent wire protocol.
_MSG_EXTENSION = 20

# BEP 9 message types
_BEP9_REQUEST = 0
_BEP9_DATA = 1
_BEP9_REJECT = 2

# The extension ids we advertise for ut_metadata and ut_pex.
_OUR_UT_METADATA_ID = 1
_OUR_UT_PEX_ID = 2

# Maximum wire message size (4 MB sanity limit).
_MAX_MESSAGE_SIZE = 4 * 1024 * 1024


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

    Raises ``ValueError`` if the message exceeds 4 MB (sanity limit to
    prevent memory exhaustion from malicious peers).
    """
    length_bytes = _recv_exact(sock, 4)
    length = struct.unpack("!I", length_bytes)[0]
    if length == 0:
        return None  # keep-alive
    if length > _MAX_MESSAGE_SIZE:
        raise ValueError("Message too large: %d" % length)
    data = _recv_exact(sock, length)
    return data[0], data[1:]


def _send_ext_handshake(sock: socket.socket) -> None:
    """Send our BEP 10 extension handshake advertising ut_metadata and ut_pex."""
    handshake_dict = {
        b"m": {
            b"ut_metadata": _OUR_UT_METADATA_ID,
            b"ut_pex": _OUR_UT_PEX_ID,
        },
        b"metadata_size": 0,
    }
    _send_extension_message(sock, 0, bencode(handshake_dict))


def _parse_ext_handshake(payload: bytes) -> dict:
    """
    Parse the peer's extension handshake payload.

    Returns
    -------
    dict
        ``ut_metadata_id`` (int): The peer's message id for ut_metadata.
        ``metadata_size`` (int): Total metadata size in bytes.
        ``ut_pex_id`` (int or None): The peer's message id for ut_pex,
        or ``None`` if the peer does not support PEX.

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
    return {
        "ut_metadata_id": int(ut_metadata_id),
        "metadata_size": int(metadata_size),
        "ut_pex_id": int(m[b"ut_pex"]) if b"ut_pex" in m else None,
    }


def _parse_pex_message(payload: bytes) -> tuple[int, int]:
    """
    Parse a PEX (ut_pex / BEP 11) message payload.

    Returns
    -------
    seed_count : int
        Number of seeds (upload-only peers) in the added set.
    peer_count : int
        Total number of peers in the added set.
    """
    d, _ = bdecode_rest(payload)
    added = d.get(b"added", b"")
    flags = d.get(b"added.f", b"")
    added6 = d.get(b"added6", b"")
    flags6 = d.get(b"added6.f", b"")

    total_peers = len(added) // 6 + len(added6) // 18
    seeds = 0

    # Count seeds from IPv4 flags
    for i in range(min(len(flags), len(added) // 6)):
        if flags[i] & 0x02:  # seed/upload-only flag
            seeds += 1

    # Count seeds from IPv6 flags
    for i in range(min(len(flags6), len(added6) // 18)):
        if flags6[i] & 0x02:
            seeds += 1

    return seeds, total_peers


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
        peer_info = None
        while True:
            msg = _recv_message(sock)
            if msg is None:
                continue  # keep-alive
            msg_id, payload = msg
            if msg_id == _MSG_EXTENSION and len(payload) >= 1:
                ext_id = payload[0]
                if ext_id == 0:
                    try:
                        peer_info = _parse_ext_handshake(payload[1:])
                    except ValueError:
                        return None
                    break

        if peer_info is None or peer_info["metadata_size"] <= 0:
            return None

        # ── BEP 9 metadata download ─────────────────────────────────────
        ut_metadata_id = peer_info["ut_metadata_id"]
        metadata_size = peer_info["metadata_size"]
        num_pieces = math.ceil(metadata_size / _PIECE_SIZE)
        pieces: dict[int, bytes] = {}

        # Request all pieces upfront.
        for piece_idx in range(num_pieces):
            request_payload = bencode(
                {b"msg_type": _BEP9_REQUEST, b"piece": piece_idx}
            )
            _send_extension_message(sock, ut_metadata_id, request_payload)

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


def fetch_metadata_extended(
    info_hash: bytes,
    peer_ip: str,
    peer_port: int,
    timeout: float = 15.0,
    pex_wait: float = 3.0,
) -> dict | None:
    """
    Like :func:`fetch_metadata` but also collects PEX (BEP 11) peer/seed counts.

    Performs the same BEP 9 metadata download, but additionally watches for
    PEX messages during the transfer and optionally waits briefly after
    metadata is complete to receive a PEX message.

    Args:
        info_hash: 20-byte info hash.
        peer_ip: Peer IP address.
        peer_port: Peer TCP port.
        timeout: Connection/read timeout in seconds.
        pex_wait: Extra seconds to wait for a PEX message after metadata
            download completes (0 to skip).

    Returns:
        A dict with keys ``'info'`` (decoded info dict), ``'seed_count'``
        (int), and ``'peer_count'`` (int), or ``None`` on failure.
    """
    peer_id = _generate_peer_id()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((peer_ip, peer_port))

        sock.sendall(_build_handshake(info_hash, peer_id))
        _, _, supports_ext = _recv_handshake(sock)
        if not supports_ext:
            return None

        _send_ext_handshake(sock)

        peer_info = None
        while True:
            msg = _recv_message(sock)
            if msg is None:
                continue
            msg_id, payload = msg
            if msg_id == _MSG_EXTENSION and len(payload) >= 1:
                ext_id = payload[0]
                if ext_id == 0:
                    try:
                        peer_info = _parse_ext_handshake(payload[1:])
                    except ValueError:
                        return None
                    break

        if peer_info is None or peer_info["metadata_size"] <= 0:
            return None

        ut_metadata_id = peer_info["ut_metadata_id"]
        ut_pex_id = peer_info.get("ut_pex_id")
        metadata_size = peer_info["metadata_size"]
        num_pieces = math.ceil(metadata_size / _PIECE_SIZE)
        pieces: dict[int, bytes] = {}

        for piece_idx in range(num_pieces):
            request_payload = bencode(
                {b"msg_type": _BEP9_REQUEST, b"piece": piece_idx}
            )
            _send_extension_message(sock, ut_metadata_id, request_payload)

        seed_count = 0
        peer_count = 0

        # Collect metadata pieces, also watch for PEX messages
        while len(pieces) < num_pieces:
            msg = _recv_message(sock)
            if msg is None:
                continue
            msg_id, payload = msg
            if msg_id != _MSG_EXTENSION:
                continue
            if len(payload) < 2:
                continue
            ext_id = payload[0]

            if ext_id == _OUR_UT_PEX_ID and ut_pex_id is not None:
                try:
                    s, p = _parse_pex_message(payload[1:])
                    seed_count = max(seed_count, s)
                    peer_count = max(peer_count, p)
                except Exception:
                    pass
                continue

            if ext_id != _OUR_UT_METADATA_ID:
                continue

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

        metadata = b"".join(pieces[i] for i in range(num_pieces))

        if len(metadata) != metadata_size:
            return None
        if hashlib.sha1(metadata).digest() != info_hash:
            return None

        info_dict, _ = bdecode_rest(metadata)

        # Wait briefly for PEX message if we haven't gotten one yet
        if peer_count == 0 and ut_pex_id is not None and pex_wait > 0:
            sock.settimeout(pex_wait)
            deadline = time.time() + pex_wait
            try:
                while time.time() < deadline:
                    msg = _recv_message(sock)
                    if msg is None:
                        continue
                    msg_id, payload = msg
                    if msg_id == _MSG_EXTENSION and len(payload) >= 2:
                        ext_id = payload[0]
                        if ext_id == _OUR_UT_PEX_ID:
                            try:
                                s, p = _parse_pex_message(payload[1:])
                                seed_count = max(seed_count, s)
                                peer_count = max(peer_count, p)
                            except Exception:
                                pass
                            break
            except (socket.timeout, TimeoutError):
                pass

        return {
            "info": info_dict,
            "seed_count": seed_count,
            "peer_count": peer_count,
        }

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


def fetch_extended_from_peers(
    info_hash: bytes,
    peers: list[tuple[str, int]],
    timeout: float = 10.0,
) -> dict | None:
    """
    Try multiple peers using extended fetch (metadata + PEX counts).

    Args:
        info_hash: 20-byte info hash.
        peers: List of ``(ip, port)`` tuples.
        timeout: Per-peer connection/read timeout in seconds.

    Returns:
        A dict with ``'info'``, ``'seed_count'``, ``'peer_count'``, or ``None``.
    """
    for peer_ip, peer_port in peers:
        result = fetch_metadata_extended(
            info_hash, peer_ip, peer_port, timeout=timeout
        )
        if result is not None:
            return result
    return None
