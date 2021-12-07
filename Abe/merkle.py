"""Tools for determining the Merkle roots of different data types."""

from typing import List, Tuple
from util import SHA256D64, double_sha256, NULL_HASH


#    WARNING! If you're reading this because you're learning about crypto
#    and/or designing a new system that will use merkle trees, keep in mind
#    that the following merkle tree algorithm has a serious flaw related to
#    duplicate txids, resulting in a vulnerability (CVE-2012-2459).
#    The reason is that if the number of hashes in the list at a given level
#    is odd, the last one is duplicated before computing the next level (which
#    is unusual in Merkle trees). This results in certain sequences of
#    transactions leading to the same merkle root. For example, these two
#    trees:
#                 A               A
#               /  \            /   \
#             B     C         B       C
#            / \    |        / \     / \
#           D   E   F       D   E   F   F
#          / \ / \ / \     / \ / \ / \ / \
#          1 2 3 4 5 6     1 2 3 4 5 6 5 6
#    for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
#    6 are repeated) result in the same root hash A (because the hash of both
#    of (F) and (F,F) is C).
#    The vulnerability results from being able to send a block with such a
#    transaction list, with the same merkle root, and the same block hash as
#    the original without duplication, resulting in failed validation. If the
#    receiving node proceeds to mark that block as permanently invalid
#    however, it will fail to accept further unmodified (and thus potentially
#    valid) versions of the same block. We defend against this by detecting
#    the case where we would hash two identical hashes at the end of the list
#    together, and treating that identically to the block having an invalid
#    merkle root. Assuming no double-SHA256 collisions, this will detect all
#    known ways of changing the transactions without affecting the merkle
#    root.


class Merkle:
    """Class container used to compute the Merkle root of lists of either raw data of of hashes.

    Args:
        `hashes` (List[bytes]): List of hashes or data used to compute the Merkle root.

    Methods:
        `root()`: Returns the Merkle root of a list of hashes.
        `block_root()`: Returns a tuple containing the Merkle root of a list of input bytes and
        a boolean of if there were any hash collissions due to mutation.
        `block_witness_root()`: Returns a tuple containing the Merkle root of a list of input bytes
        and a boolean of if there were any hash collissions due to mutation.

    """

    def __init__(self, data: List[bytes]):
        self.leaves: List[bytes] = data
        self.hashes: List[bytes]
        self.mutated: bool

    # Based on consensus/merkle.h::ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated)
    def root(self) -> bytes:
        """Returns the Merkle root of a list of hashes.

        This method is accessed via:
        - `Merkle(list_of_input_hashes).root()`

        Raises:
            IndexError: A zero length block was passed.

        Returns:
            bytes: If len(hashes) == 0 this returns b"" otherwise it returns the Merkle root.
        """

        hashes: List[bytes]
        try:
            hashes = self.hashes
        except (NameError, AttributeError):
            hashes = self.leaves

        if len(hashes) == 0:
            # return b""
            raise IndexError("A zero length hash vector was passed.")

        mutation: bool = False

        while len(hashes) > 1:

            size: int = len(hashes)

            for i in (j for j in range(0, size, 2) if j + 1 < size):
                if hashes[i] == hashes[i + 1]:
                    mutation = True

            if size & 1:
                hashes.append(hashes[-1])
                size += 1

            hashes = SHA256D64(hashes)
            # There is a difference with the reference SHA256D64 and what is here:
            # SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
            # hashes.resize(hashes.size() / 2);

        self.mutated = mutation

        return hashes[0]

    # Based on consensus/merkle.h::BlockMerkleRoot(const CBlock& block, bool* mutated)
    def block_root(self) -> Tuple[bytes, bool]:
        """Returns a tuple containing the Merkle root of a list of input bytes and a boolean of if
        there were any hash collissions due to mutation.

        This method is accessed via:
        - `Merkle(list_of_input_bytes).block_root()`

        Raises:
            IndexError: "(None) was passed."

        Returns:
            Tuple[bytes, bool]: Tuple of the root hash and if there were any mutations
        """

        size: int = len(self.leaves)
        if size == 0:
            # return b""
            raise IndexError("A zero length block was passed.")

        self.hashes = [NULL_HASH] * size

        for i, value in enumerate(self.leaves):
            self.hashes[i] = double_sha256(value)

        return (self.root(), self.mutated)

    # Based on consensus/merkle.h::BlockWitnessMerkleRoot(const CBlock& block, bool* mutated)
    def block_witness_root(self) -> Tuple[bytes, bool]:
        """Returns a tuple containing the Merkle root of a list of input bytes
        and a boolean of if there were any hash collissions due to mutation.

        This method is accessed via:
        - `Merkle(list_of_input_bytes).block_witness_root()`

        Raises:
            IndexError: "(None) was passed."

        Returns:
            Tuple[bytes, bool]: Tuple of the root hash and if there were any mutations
        """

        size: int = len(self.leaves)
        if size == 0:
            # return b""
            raise IndexError("A zero length witness block was passed.")

        self.hashes = [NULL_HASH] * size  # The witness hash of the coinbase is 0.

        for i in (j for j in range(1, size) if size > 1):
            self.hashes[i + 1] = double_sha256(self.leaves[i + 1])

        return (self.root(), self.mutated)
