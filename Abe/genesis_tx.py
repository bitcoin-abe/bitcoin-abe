# Copyright(C) 2013 by Abe developers.

# genesis_tx.py: known transactions unavailable through RPC for
# historical reasons: https://bitcointalk.org/index.php?topic=119530.0

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

def get(tx_hash_hex):
    """
    Given the hexadecimal hash of the genesis transaction (as shown
    by, e.g., "bitcoind getblock 0") return the hexadecimal raw
    transaction.  This works around a Bitcoind limitation described at
    https://bitcointalk.org/index.php?topic=119530.0
    """

    # Main Bitcoin chain:
    if tx_hash_hex == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b":
        return "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

    # Extract your chain's genesis transaction data from the first
    # block file and add it here, or better yet, patch your coin's
    # getrawtransaction to return it on request:
    #if tx_hash_hex == "<HASH>"
    #    return "<DATA>"

    return None
