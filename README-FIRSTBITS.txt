FIRSTBITS PRELIMINARY NOTES

I intend for Abe to support bidirectional translation between
addresses and firstbits as on http://firstbits.com/.  This involves
three steps:

1. an upgrade option to compute and store firstbits of addresses
   (pubkeys) currently in the database,

2. additional block-importing code to compute and store new firstbits
   found in a block, and

3. front-end UI/API.

Step #1 is done.  The following commands create and populate the
abe_firstbits table, given a database using the latest code from
bitcoin-abe's "master" branch.  Replace "--config DB.conf" with your
database connection parameters.  For a large database, this may take
hours:

    git checkout firstbits
    python -m Abe.abe --config DB.conf --use-firstbits --upgrade

Currenty, this exits with an error message, "Exception: firstbits
implementation is incomplete, aborting upgrade," after it creates the
table.  To continue using Abe, you must switch back to the master
branch:

    git checkout master

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

The following design notes pertain to developing the remaining parts,
in particular Step #2 above.


FIRSTBITS DESIGN

Maintenance of the abe_firstbits table will impose space and time
costs on Abe instances.  To keep things simple, I do not plan to
support firstbits calculation in some chains and not others.  If
use_firstbits is in effect, a new database invariant will require the
table to contain all firstbits corresponding to chain_candidate rows
where block_height is not null.  If use_firstbits is false (the
default) then Abe will behave as before and not touch abe_firstbits.

Finding firstbits requires a function that determines whether a given
block is descended from another given block.  Why?  Because several
firstbits records may collide with initial substrings of the new
address, but only the ones in ancestral blocks can prevent it from
receiving the firstbits.

Abe currently implements the descended-from relationship in
DataStore.is_descended_from, used in calculating coin-days destroyed.
This function suffers from two problems, which I would like to fix
while adding firstbits support.  One, it is very complex.  Two, it
relies heavily on most blocks belonging to a longest chain, so its
performance may suffer in the presence of long side-chains, such as
those created during 51% attacks.  The descended-from relationship is
logically independent of any notion of longest chain.

A naive implementation of is_descended_from(block, ancestor) would
simply look up block's prev_block_id in the block table and repeat
until it finds the block at ancestor's block_height.  The result would
be true iff that block is ancestor.  But this would scale linearly
with chain length, and I would like a faster function.

A naive, fast implementation would introduce a block_ancestor table
containing a row for each block pair whose first block is descended
from its second block.  But this table would grow as the square of the
chain length, and that is too big.

In implementing the upgrade.py function that populates firstbits from
existing block data, I created ancestry.py, which implements
is_descended_from (in memory) with a compromise between size and
speed.  My initial thought was to reuse this code in DataStore.py for
the maintenance portion, but I am considering an alternative approach
involving a new block table column, ancestor_block_id.

Like block.prev_block_id, ancestor_block_id would point to an earlier
block in the chain, but the earlier block's height would be found by a
function other than block_height-1.  The function would depend only on
block_height and should allow is_descended_from to use a more-or-less
binary search.  Here is a paper by Chris Okasaki describing a similar
structure: "Purely Functional Random-Access Lists"
http://cs.oberlin.edu/~jwalker/refs/fpca95.ps

The _next_express function in ancestry.py is something like the
function I want for ancestor_block_id height:

    def _next_express(n):
        bit = 1
        while bit & n:
            bit <<= 1
        return n - bit

I could improve on this a bit: even numbers n always produce n-1,
which is redundant with prev_block_id.  Perhaps even numbers should
give n/2.  But then, two blocks with even heights n and n-2 would give
almost the same information, so perhaps n divisible by 4 should give
n-n/4 and n divisible by 2**k should give n - n/(2**k).  And so forth.

Given this information, it would be possible to write
is_descended_from as a stored procedure in databases that support it.
This would be an optional performance and utility improvement, though.
Abe would contain the same logic in generic Python code.

An alternative table-based approach is libbitcoin's span_left and
span_right.  I have not got my head around the requirements for
adjusting the span values when new side chains appear, though, and I
think my more-or-less binary search will suffice.
