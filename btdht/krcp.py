# -*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015 Valentin Samir
import os

from . import utils
from .exceptions import MissingT, DecodeError


class BError(Exception):
    """
        A base class exception for all bittorrent DHT protocol error exceptions

        :param bytes t: The value of the key t of the query for with the error is returned
        :param list e: A couple [error code, error message]
    """
    #: The ``y`` key of the error message. For an error message, it is always ``b"e"``
    y = b"e"
    #: string value representing a transaction ID, must be set to the query transaction ID
    #: for which an error is raises.
    t = None
    # A list. The first element is an :class:`int` representing the error code.
    # The second element is a string containing the error message
    e = None
    def __init__(self, t, e, **kwargs):
        if t is None:
            raise ValueError("t should not be None")
        self.t = t
        self.e = e
        super(BError, self).__init__(*e, **kwargs)

    def encode(self):
        """
            Bencode the error message

            :return: The bencoded error message ready to be send
            :rtype: bytes
        """
        return utils.bencode({b"y":self.y, b"t":self.t, b"e":self.e})

    def __str__(self):
        raise NotImplementedError()

    def __repr__(self):
        return "%s: %r" % (self.__class__.__name__, self.e)

class GenericError(BError):
    """
        A Generic Error, error code 201

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b""):
        super(GenericError, self).__init__(t=t, e=[201, msg])
class ServerError(BError):
    """
        A Server Error, error code 202

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b"Server Error"):
        super(ServerError, self).__init__(t=t, e=[202, msg])
class ProtocolError(BError):
    """
        A Protocol Error, such as a malformed packet, invalid arguments, or bad token,
        error code 203

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b"Protocol Error"):
        super(ProtocolError, self).__init__(t=t, e=[203, msg])
class MethodUnknownError(BError):
    """
        Method Unknown, error code 204

        :param bytes t: The value of the key t of the query for with the error is returned
        :param bytes msg: An optionnal error message
    """
    def __init__(self, t, msg=b"Method Unknow"):
        super(MethodUnknownError, self).__init__(t=t, e=[204, msg])


class BMessage:
    """
        A bittorrent DHT message. This class is able to bdecode a bittorrent DHT message. It
        expose then the messages keys ``t``, ``y``, ``q``,  ``errno``, ``errmsg`` and ``v`` as
        attributes, and behave itself as a dictionnary for the ``a`` or ``r`` keys that contains
        a secondary dictionnary (see Notes).

        :param tuple addr: An optionnal coupe (ip, port) of the sender of the message
        :param bool debug: ``True`` for enabling debug message. The default is ``False``

        Notes:
            A query message is always of the following form with ``y == b'q'``::

                {
                    "t": t,
                    "y": y,
                    "q": q,
                    "a": {...}
                }

            A response message is always of the following form with ``y == b'r'``::

                {
                    "t": t,
                    "y": y,
                    "r": {...}
                }

            An error message is always in response of a query message and of the following form
            with ``y == b'e'``::

                {
                    "t": t,
                    "y": y,
                    "e":[errno, errmsg]
                }

            The ``t`` key is a random string generated with every query. It is used to match
            a response to a particular query.

            The ``y`` key is used to differenciate the type of the message. Its value is ``b'q'``
            for a query, ``b'r'`` for a response, and ``b'e'`` for and error message.

            The ``q`` is only present on query message and contain the name of the query (ping,
            get_peers, announce_peer, find_node)

            ``errno`` and ``errmsg`` are only defined if the message is an error message. They are
            respectively the error number (:class:`int`) and the error describing message of the error.

            The ``v`` key is set by some DHT clients to the name and version of the client and
            is totally optionnal in the protocol.
    """

    def __init__(self, addr=None, debug=False):
        self.debug = bool(debug)
        self._y = None
        self.has_y = False
        self._t = None
        self.has_t = False
        self._q = None
        self.has_q = False
        self._v = None
        self.has_v = False
        self.r = False
        self.a = False
        self.e = False
        self._errno = 0
        self._errmsg = None
        self.id = None
        self.has_id = False
        self.target = None
        self.has_target = False
        self.info_hash = None
        self.has_info_hash = False
        self.implied_port = 0
        self.has_implied_port = False
        self.port = 0
        self.has_port = False
        self.token = None
        self.has_token = False
        self.nodes = None
        self.has_nodes = False
        self.values = None
        self.has_values = False
        self.samples = None
        self.has_samples = False
        self.num = 0
        self.has_num = False
        self.interval = 0
        self.has_interval = False
        self.encoded = None
        self.encoded_uptodate = False
        self.failed = False
        self.failed_msg = None
        self._addr_addr = None
        self._addr_port = 0
        self.addr = addr

    @property
    def errno(self):
        """The error number of the message if the message is an error message"""
        if self.e:
            return self._errno
        else:
            return None

    @errno.setter
    def errno(self, value):
        self.encoded_uptodate = False
        self._errno = int(value)

    @property
    def errmsg(self):
        """The error message of the message if the message is an error message"""
        if self.e:
            return self._errmsg
        else:
            return None

    @errmsg.setter
    def errmsg(self, msg):
        self.encoded_uptodate = False
        self._errmsg = bytes(msg)

    @property
    def addr(self):
        """The couple (ip, port) source of the message"""
        if self._addr_addr and self._addr_port > 0:
            return (self._addr_addr, self._addr_port)
        else:
            return None

    @addr.setter
    def addr(self, addr):
        if addr is not None:
            self._addr_addr = addr[0]
            self._addr_port = addr[1]
        else:
            self._addr_addr = None
            self._addr_port = 0

    @addr.deleter
    def addr(self):
        self._addr_addr = None
        self._addr_port = 0

    @property
    def y(self):
        """The ``y`` key of the message. Possible values are ``b"q"`` for a query,
        ``b"r"`` for a response, and ``b"e"`` for an error."""
        if self.has_y:
            return self._y
        else:
            return None

    @y.setter
    def y(self, value):
        self.encoded_uptodate = False
        self.has_y = True
        self._y = bytes(value)

    @y.deleter
    def y(self):
        if self.has_y:
            self.encoded_uptodate = False
            self.has_y = False
            self._y = None

    @property
    def t(self):
        """The ``t`` key, a random string, transaction id used to match queries and
        responses together."""
        if self.has_t:
            return self._t
        else:
            return None

    @t.setter
    def t(self, value):
        self.encoded_uptodate = False
        self.has_t = True
        self._t = bytes(value)

    @t.deleter
    def t(self):
        if self.has_t:
            self.encoded_uptodate = False
            self.has_t = False
            self._t = None

    @property
    def q(self):
        """The ``q`` key of the message, should only be defined if the message is a query
        (:attr:`y` is ``b"q"``). It contains the name of the RPC method the query is asking for."""
        if self.has_q:
            return self._q
        else:
            return None

    @q.setter
    def q(self, value):
        self.encoded_uptodate = False
        self.has_q = True
        self._q = bytes(value)

    @q.deleter
    def q(self):
        if self.has_q:
            self.encoded_uptodate = False
            self.has_q = False
            self._q = None

    @property
    def v(self):
        """The ``v`` key of the message. Used as a version flag by many clients."""
        if self.has_v:
            return self._v
        else:
            return None

    @v.setter
    def v(self, value):
        self.encoded_uptodate = False
        self.has_v = True
        self._v = bytes(value)

    @v.deleter
    def v(self):
        if self.has_v:
            self.encoded_uptodate = False
            self.has_v = False
            self._v = None

    def response(self, dht):
        """
            If the message is a query, return the response message to send

            :param dht.DHT_BASE dht: The dht instance from which the message is originated
            :return: A :class:`BMessage` to send as response to the query
            :raises ProtocolError: if the query is malformated. To send as response to the querier
            :raises MethodUnknownError: If the RPC DHT method asked in the query is unknown.
                To send as response to the querier
        """
        rep = BMessage()
        myid = dht.myid.value
        if self.has_y and self._y == b"q":
            if self.has_q:
                if self._q == b"ping":
                    rep.y = b"r"
                    rep.t = self._t
                    rep.r = True
                    rep[b"id"] = myid
                    return rep
                elif self._q == b"find_node":
                    if not self.has_target:
                        raise ProtocolError(self.t, b"target missing")
                    rep.y = b"r"
                    rep.t = self._t
                    rep.r = True
                    rep[b"id"] = myid
                    s = dht.get_closest_nodes(self.target[:20], compact=True)
                    rep[b"nodes"] = s
                    return rep
                elif self._q == b"get_peers":
                    if not self.has_info_hash:
                        raise ProtocolError(self.t, b"info_hash missing")
                    rep.y = b"r"
                    rep.t = self._t
                    rep.r = True
                    rep[b"id"] = myid
                    token = dht._get_token(self.addr[0])
                    rep[b"token"] = token
                    peers = dht._get_peers(self.info_hash[:20])
                    if peers:
                        rep[b"values"] = peers
                    else:
                        s = dht.get_closest_nodes(self.info_hash[:20], compact=True)
                        rep[b"nodes"] = s
                    return rep
                elif self._q == b"announce_peer":
                    if not self.has_info_hash:
                        raise ProtocolError(self.t, b"info_hash missing")
                    if not self.has_port:
                        raise ProtocolError(self.t, b"port missing")
                    if not self.has_token:
                        raise ProtocolError(self.t, b"token missing")
                    valid_tokens = dht._get_valid_token(self.addr[0])
                    if self[b"token"] not in valid_tokens:
                        raise ProtocolError(self.t, b"bad token")
                    rep.y = b"r"
                    rep.t = self._t
                    rep.r = True
                    rep[b"id"] = myid
                    return rep
                elif self._q == b"sample_infohashes":
                    if not self.has_target:
                        raise ProtocolError(self.t, b"target missing")
                    rep.y = b"r"
                    rep.t = self._t
                    rep.r = True
                    rep[b"id"] = myid
                    # Return closest nodes to target
                    s = dht.get_closest_nodes(self.target[:20], compact=True)
                    rep[b"nodes"] = s
                    # Sample from our stored peers
                    import random
                    all_hashes = list(dht._peers.keys()) + list(dht._got_peers.keys())
                    sample_size = min(len(all_hashes), 20)
                    if all_hashes:
                        sampled = random.sample(all_hashes, sample_size)
                        rep[b"samples"] = b"".join(h[:20] for h in sampled)
                    else:
                        rep[b"samples"] = b""
                    rep[b"num"] = len(all_hashes)
                    rep[b"interval"] = 60
                    return rep
                else:
                    raise MethodUnknownError(self.t, b"Method %s Unknown" % self.q)

    def _build_secondary_dict(self):
        """Build the secondary dictionary (the 'a' or 'r' dict contents)."""
        d = {}
        if self.has_id:
            d[b"id"] = self.id[:20]
        if self.has_implied_port:
            d[b"implied_port"] = self.implied_port
        if self.has_info_hash:
            d[b"info_hash"] = self.info_hash[:20]
        if self.has_nodes:
            d[b"nodes"] = self.nodes
        if self.has_port:
            d[b"port"] = self.port
        if self.has_target:
            d[b"target"] = self.target[:20]
        if self.has_token:
            d[b"token"] = self.token
        if self.has_values:
            d[b"values"] = self.values
        if self.has_samples:
            d[b"samples"] = self.samples
        if self.has_num:
            d[b"num"] = self.num
        if self.has_interval:
            d[b"interval"] = self.interval
        return d

    def _encode(self):
        """
            Bencode the current message

            :return: True if the message is successfully bencoded, False otherwise
        """
        d = {}
        if self.a:
            d[b"a"] = self._build_secondary_dict()
        if self.e:
            d[b"e"] = [self._errno, self._errmsg if self._errmsg else b""]
        if self.has_q:
            d[b"q"] = self._q
        if self.r:
            d[b"r"] = self._build_secondary_dict()
        if self.has_t:
            d[b"t"] = self._t
        if self.has_v:
            d[b"v"] = self._v
        if self.has_y:
            d[b"y"] = self._y
        try:
            self.encoded = utils.bencode(d)
            self.encoded_uptodate = True
            return True
        except Exception:
            self.encoded = None
            self.encoded_uptodate = False
            return False

    def encode(self):
        """
            Bencoded the current message if necessary

            :return: The bencoded message
            :rtype: bytes
        """
        if self.encoded_uptodate:
            return self.encoded
        else:
            self._encode()
        if self.encoded_uptodate:
            return self.encoded
        else:
            raise EnvironmentError("Unable to encode BMessage")

    def __repr__(self):
        return "%r" % self.encode()

    def __str__(self):
        raise NotImplementedError()

    def __getitem__(self, key):
        """
            Allow to fetch infos from the secondary dictionnary::

                self[b"id"] -> b"..."

            :param bytes key: The name of an attribute of the secondary dictionnary to retreive.
            :return: The value store for ``key`` if found
            :raises KeyError: if ``key`` is not found

            Notes:
                Possible keys are:
                  * id
                  * target
                  * info_hash
                  * token
                  * nodes
                  * implied_port
                  * port
                  * values
        """
        if key == b"id" and self.has_id:
            return self.id[:20]
        elif key == b"target" and self.has_target:
            return self.target[:20]
        elif key == b"info_hash" and self.has_info_hash:
            return self.info_hash[:20]
        elif key == b"token" and self.has_token:
            return self.token
        elif key == b"nodes" and self.has_nodes:
            return self.nodes
        elif key == b"implied_port" and self.has_implied_port:
            return self.implied_port
        elif key == b"port" and self.has_port:
            return self.port
        elif key == b"values" and self.has_values:
            return list(self.values)
        elif key == b"samples" and self.has_samples:
            return self.samples
        elif key == b"num" and self.has_num:
            return self.num
        elif key == b"interval" and self.has_interval:
            return self.interval
        else:
            raise KeyError(key)

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __delitem__(self, key):
        """
            Allow to unset attributes from the secondary dictionnary::

                del self[b'id']

            :param bytes key: The name of an attribute of the secondary dictionnary to unset
            :return: ``True`` if ``key`` is found and successfully unset
            :raise KeyError: if ``key`` is not found
        """
        if self.has_id and key == b"id":
            self.has_id = False
            self.id = None
            self.encoded_uptodate = False
        elif self.has_target and key == b"target":
            self.has_target = False
            self.target = None
            self.encoded_uptodate = False
        elif self.has_info_hash and key == b"info_hash":
            self.has_info_hash = False
            self.info_hash = None
            self.encoded_uptodate = False
        elif self.has_token and key == b"token":
            self.has_token = False
            self.token = None
            self.encoded_uptodate = False
        elif self.has_nodes and key == b"nodes":
            self.has_nodes = False
            self.nodes = None
            self.encoded_uptodate = False
        elif self.has_implied_port and key == b"implied_port":
            self.has_implied_port = False
            self.encoded_uptodate = False
        elif self.has_port and key == b"port":
            self.has_port = False
            self.encoded_uptodate = False
        elif self.has_values and key == b"values":
            self.has_values = False
            self.values = None
            self.encoded_uptodate = False
        elif self.has_samples and key == b"samples":
            self.has_samples = False
            self.samples = None
            self.encoded_uptodate = False
        elif self.has_num and key == b"num":
            self.has_num = False
            self.num = 0
            self.encoded_uptodate = False
        elif self.has_interval and key == b"interval":
            self.has_interval = False
            self.interval = 0
            self.encoded_uptodate = False
        else:
            raise KeyError(key)

    def __setitem__(self, key, value):
        """
            Allow to set attributes from the secondary dictionnary::

                self[b'id'] = b"..."

            :param bytes key: The name of an attribute of the secondary dictionnary to set
            :param value: The value to set
            :raises KeyError: if ``key`` is not one of id, target, info_hash, token, nodes,
                implied_port, port, values.
            :raises ValueError: if ``value`` is not well formated (length, type, ...)
        """
        self.encoded_uptodate = False
        if key == b"id":
            if len(value) != 20:
                raise ValueError("Can only set strings of length 20B")
            self.has_id = True
            self.id = bytes(value)
        elif key == b"target":
            if len(value) != 20:
                raise ValueError("Can only set strings of length 20B")
            self.has_target = True
            self.target = bytes(value)
        elif key == b"info_hash":
            if len(value) != 20:
                raise ValueError("Can only set strings of length 20B")
            self.has_info_hash = True
            self.info_hash = bytes(value)
        elif key == b"token":
            self.has_token = True
            self.token = bytes(value)
        elif key == b"nodes":
            self.has_nodes = True
            self.nodes = bytes(value)
        elif key == b"implied_port":
            self.has_implied_port = True
            self.implied_port = int(value)
        elif key == b"port":
            self.has_port = True
            self.port = int(value)
        elif key == b"values":
            self.has_values = True
            self.values = [bytes(v) for v in value]
        elif key == b"samples":
            self.has_samples = True
            self.samples = bytes(value)
        elif key == b"num":
            self.has_num = True
            self.num = int(value)
        elif key == b"interval":
            self.has_interval = True
            self.interval = int(value)
        else:
            raise KeyError(key)

    def get(self, key, default=None):
        """
            :param bytes key: The name of an attribute of the secondary dictionnary to retreive.
            :param default: Value to return in case ``key`` is not found. The default is ``None``
            :return: The value of ``key`` if found, else the value of ``default``.
        """
        try:
            return self[key]
        except KeyError:
            return default

    def decode(self, data, datalen):
        """
            Bdecode a bencoded message and set the current :class:`BMessage` attributes accordingly

            :param bytes data: The bencoded message
            :param int datalen: The length of ``data``
            :return: The remaining of ``data`` after the first bencoded message of ``data`` has been
                bdecoded (it may be the empty string if ``data`` contains exactly one bencoded
                message with no garbade at the end).
            :raises DecodeError: If we fail to decode the message
            :raises ProtocolError: If the message is decoded but some attributes are missing of
                badly formated (length, type, ...).
            :raises MissingT: If the message do not have a ``b"t"`` key. Indeed,
                accordingly to the BEP5, every message (queries, responses, errors) should have
                a ``b"t"`` key.
        """
        if not isinstance(data, bytes):
            data = bytes(data)
        data = data[:datalen]
        if len(data) == 0:
            return b""

        try:
            decoded, remainder = _bdecode_msg(data)
        except Exception as exc:
            raise DecodeError(str(exc)) from exc

        if not isinstance(decoded, dict):
            raise DecodeError("Expected a dict at top level")

        # Extract top-level keys
        if b"t" in decoded:
            self.has_t = True
            self._t = bytes(decoded[b"t"])
        if b"y" in decoded:
            self.has_y = True
            self._y = bytes(decoded[b"y"])
        if b"q" in decoded:
            self.has_q = True
            self._q = bytes(decoded[b"q"])
        if b"v" in decoded:
            self.has_v = True
            self._v = bytes(decoded[b"v"])

        # Extract secondary dict (a or r)
        secondary = None
        if b"a" in decoded:
            self.a = True
            secondary = decoded[b"a"]
        if b"r" in decoded:
            self.r = True
            secondary = decoded[b"r"]
        if b"e" in decoded:
            self.e = True
            err = decoded[b"e"]
            if isinstance(err, list) and len(err) >= 2:
                self._errno = int(err[0])
                self._errmsg = bytes(err[1]) if isinstance(err[1], (bytes, bytearray)) else str(err[1]).encode()

        if secondary is not None and isinstance(secondary, dict):
            self._decode_secondary(secondary)

        if not self.has_t:
            raise MissingT()

        if self.failed:
            if self.has_y and self._y == b"q":
                raise ProtocolError(self.t, self.failed_msg)
            else:
                raise DecodeError(self.failed_msg)

        if not self.has_y:
            raise DecodeError()

        return remainder

    def _decode_secondary(self, d):
        """Decode the secondary dictionary (a or r dict contents)."""
        if b"id" in d:
            val = bytes(d[b"id"])
            if len(val) != 20:
                self.failed = True
                self.failed_msg = b"id should be of length 20"
            self.has_id = True
            self.id = val

        if b"target" in d:
            val = bytes(d[b"target"])
            if len(val) != 20:
                self.failed = True
                self.failed_msg = b"target should be of length 20"
            self.has_target = True
            self.target = val

        if b"info_hash" in d:
            val = bytes(d[b"info_hash"])
            if len(val) != 20:
                self.failed = True
                self.failed_msg = b"info_hash should be of length 20"
            self.has_info_hash = True
            self.info_hash = val

        if b"implied_port" in d:
            self.has_implied_port = True
            self.implied_port = int(d[b"implied_port"])

        if b"port" in d:
            self.has_port = True
            self.port = int(d[b"port"])

        if b"token" in d:
            self.has_token = True
            self.token = bytes(d[b"token"])

        if b"nodes" in d:
            self.has_nodes = True
            self.nodes = bytes(d[b"nodes"])

        if b"values" in d:
            val = d[b"values"]
            if isinstance(val, list):
                values = []
                for item in val:
                    item = bytes(item)
                    if len(item) != 6:
                        self.failed = True
                        self.failed_msg = b"element of values are expected to be of length 6"
                    values.append(item[:6])
                self.has_values = True
                self.values = values
            else:
                self.failed = True
                self.failed_msg = b"values items should be a list"

        if b"samples" in d:
            val = bytes(d[b"samples"])
            if len(val) % 20 != 0:
                self.failed = True
                self.failed_msg = b"samples length should be a multiple of 20"
            self.has_samples = True
            self.samples = val

        if b"num" in d:
            self.has_num = True
            self.num = int(d[b"num"])

        if b"interval" in d:
            self.has_interval = True
            self.interval = int(d[b"interval"])


def _bdecode_msg(data):
    """
    Decode a single bencoded message from data, returning (decoded_object, remainder_bytes).
    This is a simple bencoding parser.
    """
    if not data:
        raise DecodeError("Empty data")

    i = [0]  # mutable index

    def decode_next():
        if i[0] >= len(data):
            raise DecodeError("Unexpected end of data at %d" % i[0])
        ch = data[i[0]:i[0]+1]
        if ch == b'd':
            return decode_dict()
        elif ch == b'l':
            return decode_list()
        elif ch == b'i':
            return decode_int()
        elif ch[0:1] in (b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9'):
            return decode_string()
        else:
            raise DecodeError("Unexpected byte %r at %d" % (ch, i[0]))

    def decode_dict():
        if data[i[0]:i[0]+1] != b'd':
            raise DecodeError("Expected 'd' at %d" % i[0])
        i[0] += 1
        d = {}
        while i[0] < len(data) and data[i[0]:i[0]+1] != b'e':
            key = decode_string()
            val = decode_next()
            d[key] = val
        if i[0] >= len(data) or data[i[0]:i[0]+1] != b'e':
            raise DecodeError("Expected 'e' at end of dict at %d" % i[0])
        i[0] += 1
        return d

    def decode_list():
        if data[i[0]:i[0]+1] != b'l':
            raise DecodeError("Expected 'l' at %d" % i[0])
        i[0] += 1
        lst = []
        while i[0] < len(data) and data[i[0]:i[0]+1] != b'e':
            lst.append(decode_next())
        if i[0] >= len(data) or data[i[0]:i[0]+1] != b'e':
            raise DecodeError("Expected 'e' at end of list at %d" % i[0])
        i[0] += 1
        return lst

    def decode_int():
        if data[i[0]:i[0]+1] != b'i':
            raise DecodeError("Expected 'i' at %d" % i[0])
        i[0] += 1
        end = data.index(b'e', i[0])
        num_str = data[i[0]:end]
        i[0] = end + 1
        return int(num_str)

    def decode_string():
        colon = data.index(b':', i[0])
        length = int(data[i[0]:colon])
        i[0] = colon + 1
        s = data[i[0]:i[0] + length]
        i[0] += length
        return s

    result = decode_next()
    remainder = data[i[0]:]
    return result, remainder
