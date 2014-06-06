# Copyright(C) 2014 by Abe developers.

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

from .KeccakChain import KeccakChain
from .. import util

class Maxcoin(KeccakChain):
    """
    Maxcoin uses Keccak for block headers and single SHA-256 for transactions.
    """
    def __init__(chain, **kwargs):
        chain.name = 'Maxcoin'
        chain.code3 = 'MAX'
        chain.address_version = '\x6e'
        chain.script_addr_vers = '\x70'
        chain.magic = "\xf9\xbe\xbb\xd2"
        super(Maxcoin, chain).__init__(**kwargs)

    def transaction_hash(chain, binary_tx):
        return util.sha256(binary_tx)

    datadir_conf_file_name = 'maxcoin.conf'
    datadir_rpcport = 8669
