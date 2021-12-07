"""Test merkle.py"""

from Abe.merkle import Merkle
from Abe.util import hex2b, NULL_HASH
from .data import simple_block, simple_block_raw_tx, simple_block_tx_hashes


def test_genesis_block() -> None:
    """test the genesis block"""
    # pylint: disable=line-too-long
    transaction = [
        hex2b(
            "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
        )
    ]
    merkle_root = hex2b(
        "3BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A"
    )
    root, mutated = Merkle(transaction).block_root()
    assert root == merkle_root
    assert mutated is False
    root, mutated = Merkle(transaction).block_witness_root()
    assert root == NULL_HASH
    assert mutated is False


def test_simple_block() -> None:
    """Test the simple block"""
    root, mutated = Merkle(simple_block_raw_tx).block_root()
    assert root == simple_block["hashMerkleRoot"]
    assert mutated is False
    assert Merkle(simple_block_tx_hashes).root() == simple_block["hashMerkleRoot"]
