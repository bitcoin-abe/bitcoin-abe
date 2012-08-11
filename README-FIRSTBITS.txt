FIRSTBITS NOTES

Abe experimentally supports bidirectional translation between
addresses and firstbits as on http://firstbits.com/.  Abe will
disagree with other firstbits implementations in some cases until the
algorithm is better defined and all implementations start to use it.

This disagreement has security implications.  Do not rely on the
firstbits address reported by Abe to match the one on firstbits.com or
another site when sending bitcoins.  See this forum thread, and note
that Abe does not currently implement the algorithm proposed there:
https://bitcointalk.org/index.php?topic=16217.msg960077#msg960077

This feature is disabled by default due to performance impact.  To
enable it, add "use-firstbits" to the configuration *before* first
running a version that supports it.

If you run without use-firstbits, Abe will default it to false and
will never create the table.  The Abe.reconfigure module turns
firstbits on and off once you have upgraded Abe's schema.  Stop all
processes using the database, change the use-firstbits setting in
abe.conf, and run:

    python -m Abe.reconfigure --config abe.conf

I have tried a few dozen addresses, and they match firstbits.com.
Please report issues in the forum thread
(https://bitcointalk.org/index.php?topic=22785.msg949105#msg949105) or
by email, PM, or the github issue system, since I will not spend much
time testing.

The new table has four columns:

    pubkey_id - identifies a public key hash in the pubkey table
    block_id - a block where this address first appeared in its chain
    address_version - second component of address, along with pubkey_hash
    firstbits - lowercase firstbits of the address in this chain

Note that address_version for Bitcoin addresses is always "\0" (or
"00" in hex).  The field exists because Abe supports multiple
currencies with different address versions, such as Bitcoin Testnet
and Namecoin.

To get from address to pubkey_hash and address_version, use, for
example, /q/decode_address/ADDRESS.  To get from pubkey_hash and
address_version to address, use /q/hashtoaddress/HASH/VERSION.

Note that the existence of an address in the table does not always
imply that the address has the given firstbits.  It will if the
corresponding block is in the main chain.  That is, if block_id
matches a row in chain_candidate where in_longest=1 and chain_id=1
(for Bitcoin, or the desired chain_id from the chain table).


FIRSTBITS TECHNICAL DESIGN

Maintenance of the abe_firstbits table imposes space and time costs on
Abe instances.  To keep things simple, Abe does not support firstbits
calculation in only some chains and not others.  If use_firstbits is
in effect, a database invariant requires the table to contain all
firstbits corresponding to chain_candidate rows where block_height is
not null.  If use_firstbits is false (the default) then Abe does not
touch abe_firstbits.

Finding firstbits requires a function that determines whether a given
block is descended from another given block.  Why?  Because several
firstbits records may collide with initial substrings of the new
address, but only the ones in ancestral blocks can prevent it from
receiving the firstbits.

A naive implementation of is_descended_from(block, ancestor) would
simply look up block's prev_block_id in the block table and repeat
until it finds the block at ancestor's block_height.  The result would
be true iff that block is ancestor.  But this would scale linearly
with chain length, and I would like a faster function.

A naive, fast implementation would introduce a block_ancestor table
containing a row for each block pair whose first block is descended
from its second block.  But this table would grow as the square of the
chain length, and that is too big.

Abe's implementation (DataStore.is_descended_from) involves a new
block table column, search_block_id.  Like block.prev_block_id,
search_block_id points to an earlier block in the chain, but the
earlier block's height is found by a function other than
block_height-1.  The function depends only on block_height and allows
is_descended_from to use a more-or-less binary search.  A paper by
Chris Okasaki describes a somewhat similar structure: "Purely
Functional Random-Access Lists"
http://cs.oberlin.edu/~jwalker/refs/fpca95.ps

The get_search_height function in util.py computes the search_block_id
block height.  I am sure it could be improved:

    def get_search_height(n):
        if n < 2:
            return None
        if n & 1:
            return n >> 1 if n & 2 else n - (n >> 2)
        bit = 2
        while (n & bit) == 0:
            bit <<= 1
        return n - bit

To find a block's ancestor at a given height, Abe tries the search
block if it is not too far in the past.  Otherwise, it tries the
previous block.  The pattern of height distances from block to search
block should ensure reasonable worst-case performance, but I have not
proven this.

Given search_block_id, it should be possible to write
is_descended_from as a stored procedure in databases that support it.
This would be an optional performance and utility improvement, though.
Abe would contain the same logic in generic Python code.

An alternative table-based approach is libbitcoin's span_left and
span_right.  I have not got my head around the requirements for
adjusting the span values when new side chains appear, though, and I
think the more-or-less binary search suffices.

John Tobey
2012-06-09
