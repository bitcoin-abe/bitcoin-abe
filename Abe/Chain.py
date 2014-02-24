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
    #print "create(%s, %r)" % (policy, kwargs)
    if policy in [None, "Bitcoin", "Testnet", "LegacyNoBit8"]:
        return Sha256Chain(**kwargs)
    if policy == "NovaCoin":
        return NovaCoin(**kwargs)
    if policy == "CryptoCash":
        return CryptoCash(**kwargs)
    return Sha256NmcAuxPowChain(**kwargs)

class Chain(object):
    def __init__(chain, src=None, **kwargs):
        for attr in [
            'id', 'magic', 'name', 'code3', 'address_version', 'decimals']:

            if attr in kwargs:
                val = kwargs.get(attr)
            elif hasattr(chain, attr):
                continue
            elif src is not None:
                val = getattr(src, attr)
            else:
                val = None
            setattr(chain, attr, val)

    def has_feature(chain, feature):
        return False

    def ds_parse_block_header(chain, ds):
        return deserialize.parse_BlockHeader(ds)

    def ds_parse_transaction(chain, ds):
        return deserialize.parse_Transaction(ds)

    def ds_parse_block(chain, ds):
        d = chain.ds_parse_block_header(ds)
        d['transactions'] = []
        nTransactions = ds.read_compact_size()
        for i in xrange(nTransactions):
            d['transactions'].append(chain.ds_parse_transaction(ds))
        return d

    def ds_serialize_block_header(chain, block):
        import BCDataStream
        ds = BCDataStream.BCDataStream()
        ds.write_int32(block['version'])
        ds.write(block['hashPrev'])
        ds.write(block['hashMerkleRoot'])
        ds.write_uint32(block['nTime'])
        ds.write_uint32(block['nBits'])
        ds.write_uint32(block['nNonce'])
        ds.seek_file(0)
        return ds

    def serialize_block_header(chain, block):
        return chain.ds_serialize_block_header(block).input

    def ds_block_header_hash(chain, ds):
        return chain.block_header_hash(
            ds.input[ds.read_cursor : ds.read_cursor + 80])

    def transaction_hash(chain, binary_tx):
        return util.double_sha256(binary_tx)

    def parse_transaction(chain, binary_tx):
        return chain.ds_parse_transaction(util.str_to_ds(binary_tx))

    datadir_conf_file_name = "bitcoin.conf"
    datadir_rpcport = 8332

class Sha256Chain(Chain):
    def block_header_hash(chain, header):
        return util.double_sha256(header)

class NmcAuxPowChain(Chain):
    def __init__(chain, **kwargs):
        chain.block_version_bit_merge_mine = 8
        Chain.__init__(chain, **kwargs)

    def ds_parse_block_header(chain, ds):
        d = Chain.ds_parse_block_header(chain, ds)
        if d['version'] & (1 << 8):
            d['auxpow'] = deserialize.parse_AuxPow(ds)
        return d

    def has_feature(chain, feature):
        return feature == 'block_version_bit8_merge_mine'

class Sha256NmcAuxPowChain(Sha256Chain, NmcAuxPowChain):
    pass

class LtcScryptChain(Chain):
    def block_header_hash(chain, header):
        import ltc_scrypt
        return ltc_scrypt.getPoWHash(header)

class PpcPosChain(Chain):
    def ds_parse_transaction(chain, ds):
        return deserialize.parse_Transaction(ds, has_nTime=True)

    def ds_parse_block(chain, ds):
        d = Chain.ds_parse_block(chain, ds)
        d['block_sig'] = ds.read_bytes(ds.read_compact_size())
        return d

class NvcChain(LtcScryptChain, PpcPosChain):
    def has_feature(chain, feature):
        return feature == 'nvc_proof_of_stake'

class NovaCoin(NvcChain):
    def __init__(chain, **kwargs):
        chain.name = 'NovaCoin'
        chain.code3 = 'NVC'
        chain.address_version = "\x08"
        chain.magic = "\xe4\xe8\xe9\xe5"
        chain.decimals = 6
        Chain.__init__(chain, **kwargs)

    datadir_conf_file_name = "novacoin.conf"
    datadir_rpcport = 8344

class CryptoCash(NvcChain):
    def __init__(chain, **kwargs):
        chain.name = 'Cash'
        chain.code3 = 'CAS'
        chain.address_version = "\x22"
        chain.magic = "\xe4\xc6\xfe\xe7"
        Chain.__init__(chain, **kwargs)

    datadir_conf_file_name = "Cash.conf"
    datadir_rpcport = 3941
