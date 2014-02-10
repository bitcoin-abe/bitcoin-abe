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
    #print "create(%s, %r)\n" % (policy, kwargs)
    if policy in ["Bitcoin", "Testnet", "LegacyNoBit8"]:
        return Sha256Chain(**kwargs)
    if policy == "NovaCoin":
        return NovaCoin(**kwargs)
    return Sha256NmcAuxPowChain(**kwargs)

class Chain(object):
    def __init__(chain, **kwargs):
        for attr in [
            'id', 'magic', 'name', 'code3', 'address_version', 'decimals',
            'block_version_bit_merge_mine']:
            if attr in kwargs or not hasattr(chain, attr):
                setattr(chain, attr, kwargs.get(attr))

    def parse_block_header(chain, ds):
        return deserialize.parse_BlockHeader(ds)

    def parse_transaction(chain, ds):
        return deserialize.parse_Transaction(ds)

    def parse_block(chain, ds):
        d = chain.parse_block_header(ds)
        d['transactions'] = []
        nTransactions = ds.read_compact_size()
        for i in xrange(nTransactions):
            d['transactions'].append(chain.parse_transaction(ds))
        return d

class Sha256Chain(Chain):
    def block_header_hash(chain, ds):
        return util.double_sha256(
            ds.input[ds.read_cursor : ds.read_cursor + 80])

class NmcAuxPowChain(Chain):
    def __init__(chain, **kwargs):
        chain.block_version_bit_merge_mine = 8
        Chain.__init__(chain, **kwargs)

    def parse_block_header(chain, ds):
        d = Chain.parse_block_header(chain, ds)
        if d['version'] & (1 << chain.block_version_bit_merge_mine):
            d['auxpow'] = deserialize.parse_AuxPow(ds)
        return d

class Sha256NmcAuxPowChain(Sha256Chain, NmcAuxPowChain):
    pass

class LtcScryptChain(Chain):
    def block_header_hash(chain, ds):
        import ltc_scrypt
        return ltc_scrypt.getPoWHash(
            ds.input[ds.read_cursor : ds.read_cursor + 80])

class PpcPosChain(Chain):
    def parse_transaction(chain, ds):
        return deserialize.parse_Transaction(ds, has_nTime=True)

class NovaCoin(LtcScryptChain, PpcPosChain):
    def __init__(chain, **kwargs):
        chain.name = 'NovaCoin'
        chain.code3 = 'NVC'
        chain.address_version = "\x08"
        chain.magic = "\xe4\xe8\xe9\xe5"
        chain.decimals = 6
        Chain.__init__(chain, **kwargs)
