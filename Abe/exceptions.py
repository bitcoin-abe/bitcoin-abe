"""Specific Exceptions used in Abe."""
from util import b2hex


class EnumException(Exception):
    """C-like Enumeration Exception"""


class SerializationError(Exception):
    """Thrown when there's a problem deserializing or serializing"""


class InvalidBlock(Exception):
    """Exception for an invalid block."""


class MerkleRootMismatch(InvalidBlock):
    """Subset of an invalid block for mismatching Merkle Roots"""

    def __init__(self, block_hash, tx_hashes):
        self.block_hash = block_hash
        self.tx_hashes = tx_hashes
        super().__init__()

    def __str__(self):
        return f"Block header Merkle root does not match its transactions. \
                block hash={b2hex(self.block_hash[::-1])}"


class MalformedHash(ValueError):
    """Hash not properly formed"""


class MalformedAddress(ValueError):
    """Bad address"""
