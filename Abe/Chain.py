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

import deserialize
import util

def create(policy, **kwargs):
    if policy in ["Bitcoin", "Testnet", "LegacyNoBit8"]:
        #print "%s - Sha256Chain" % policy
        return Sha256Chain(**kwargs)
    #print "%s - AuxPowChain" % policy
    return AuxPowChain(**kwargs)

class AbstractChain(object):
    def __init__(chain, id, magic, name, code3, address_version):
        chain.id              = id
        chain.magic           = magic
        chain.name            = name
        chain.code3           = code3
        chain.address_version = address_version

class Sha256Chain(AbstractChain):
    def __init__(chain, **kwargs):
        AbstractChain.__init__(chain, **kwargs)
        chain.block_version_bit_merge_mine = None

    def block_header_hash(chain, ds):
        return util.double_sha256(
            ds.input[ds.read_cursor : ds.read_cursor + 80])

    def parse_block_header(chain, ds):
        return deserialize.parse_BlockHeader(ds)

    def parse_block(chain, ds):
        d = chain.parse_block_header(ds)
        d['transactions'] = []
        nTransactions = ds.read_compact_size()
        for i in xrange(nTransactions):
            d['transactions'].append(deserialize.parse_Transaction(ds))
        return d

class AuxPowChain(Sha256Chain):
    def __init__(chain, **kwargs):
        AbstractChain.__init__(chain, **kwargs)
        chain.block_version_bit_merge_mine = 8

    def parse_block_header(chain, ds):
        d = Sha256Chain.parse_block_header(chain, ds)
        if d['version'] & (1 << chain.block_version_bit_merge_mine):
            d['auxpow'] = deserialize.parse_AuxPow(ds)
        return d
