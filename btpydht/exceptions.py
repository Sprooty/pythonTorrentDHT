class BucketFull(Exception):
    """
        Raised then trying to add a node to a :class:`Bucket<btpydht.dht.Bucket>` that
        already contains :class:`Bucket.max_size<btpydht.dht.Bucket.max_size>` elements.
    """
    pass

class BucketNotFull(Exception):
    """
        Raises then trying to split a split a :class:`Bucket<btpydht.dht.Bucket>` that
        contains less than :class:`Bucket.max_size<btpydht.dht.Bucket.max_size>` elements.
    """
    pass

class NoTokenError(Exception):
    """
        Raised then trying to annonce to a node we download an info_hash
        using :meth:`Node.announce_peer<btpydht.dht.Node.announce_peer>` but we do not known any valid
        token. The error should always be catch and never seen by btpydht users.
    """
    pass

class FailToStop(Exception):
    """Raises then we are tying to stop threads but failing at it"""
    pass

class TransactionIdUnknown(Exception):
    """Raised then receiving a response with an unknown ``t`` key"""
    pass

class MissingT(ValueError):
    """Raised while decoding of a dht message if that message of no key ``t``"""
    pass

class DecodeError(ValueError):
    """Raised while decoding a dht message"""
    pass

class BcodeError(Exception):
    """Raised by :func:`btpydht.utils.bdecode` and :func:`btpydht.utils.bencode` functions"""
    pass

class NotFound(Exception):
    """
        Raised when trying to get a node that do not exists from a :class:`Bucket<btpydht.dht.Bucket>`
    """
    pass

