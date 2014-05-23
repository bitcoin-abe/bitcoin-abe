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
from deserialize import opcodes
import BCDataStream
import util

def create(policy, **kwargs):
    # XXX It's about time to interpret policy as a module name.
    if policy in [None, "Bitcoin"]: return Bitcoin(**kwargs)
    if policy == "Testnet":         return Testnet(**kwargs)
    if policy == "Namecoin":        return Namecoin(**kwargs)
    if policy == "LegacyNoBit8":    return Sha256Chain(**kwargs)
    if policy == "NovaCoin":        return NovaCoin(**kwargs)
    if policy == "CryptoCash":      return CryptoCash(**kwargs)
    if policy == "Hirocoin":        return Hirocoin(**kwargs)
    if policy == "X11":             return X11Chain(**kwargs)
    if policy == "X11Pos":          return X11PosChain(**kwargs)
    if policy == "Bitleu":          return Bitleu(**kwargs)
    if policy == "Keccak":          return KeccakChain(**kwargs)
    if policy == "Maxcoin":         return Maxcoin(**kwargs)
    return Sha256NmcAuxPowChain(**kwargs)


PUBKEY_HASH_LENGTH = 20
MAX_MULTISIG_KEYS = 3

# Template to match a pubkey hash ("Bitcoin address transaction") in
# txout_scriptPubKey.  OP_PUSHDATA4 matches any data push.
SCRIPT_ADDRESS_TEMPLATE = [
    opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]

# Template to match a pubkey ("IP address transaction") in txout_scriptPubKey.
SCRIPT_PUBKEY_TEMPLATE = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]

# Template to match a BIP16 pay-to-script-hash (P2SH) output script.
SCRIPT_P2SH_TEMPLATE = [ opcodes.OP_HASH160, PUBKEY_HASH_LENGTH, opcodes.OP_EQUAL ]

# Template to match a script that can never be redeemed, used in Namecoin.
SCRIPT_BURN_TEMPLATE = [ opcodes.OP_RETURN ]

SCRIPT_TYPE_INVALID = 0
SCRIPT_TYPE_UNKNOWN = 1
SCRIPT_TYPE_PUBKEY = 2
SCRIPT_TYPE_ADDRESS = 3
SCRIPT_TYPE_BURN = 4
SCRIPT_TYPE_MULTISIG = 5
SCRIPT_TYPE_P2SH = 6


class Chain(object):
    def __init__(chain, src=None, **kwargs):
        for attr in [
            'id', 'magic', 'name', 'code3', 'address_version', 'decimals', 'script_addr_vers']:

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

    def ds_serialize_block(chain, ds, block):
        chain.ds_serialize_block_header(ds, block)
        ds.write_compact_size(len(block['transactions']))
        for tx in block['transactions']:
            chain.ds_serialize_transaction(ds, tx)

    def ds_serialize_block_header(chain, ds, block):
        ds.write_int32(block['version'])
        ds.write(block['hashPrev'])
        ds.write(block['hashMerkleRoot'])
        ds.write_uint32(block['nTime'])
        ds.write_uint32(block['nBits'])
        ds.write_uint32(block['nNonce'])

    def ds_serialize_transaction(chain, ds, tx):
        ds.write_int32(tx['version'])
        ds.write_compact_size(len(tx['txIn']))
        for txin in tx['txIn']:
            chain.ds_serialize_txin(ds, txin)
        ds.write_compact_size(len(tx['txOut']))
        for txout in tx['txOut']:
            chain.ds_serialize_txout(ds, txout)
        ds.write_uint32(tx['lockTime'])

    def ds_serialize_txin(chain, ds, txin):
        ds.write(txin['prevout_hash'])
        ds.write_uint32(txin['prevout_n'])
        ds.write_string(txin['scriptSig'])
        ds.write_uint32(txin['sequence'])

    def ds_serialize_txout(chain, ds, txout):
        ds.write_int64(txout['value'])
        ds.write_string(txout['scriptPubKey'])

    def serialize_block(chain, block):
        ds = BCDataStream.BCDataStream()
        chain.ds_serialize_block(ds, block)
        return ds.input

    def serialize_block_header(chain, block):
        ds = BCDataStream.BCDataStream()
        chain.ds_serialize_block_header(ds, block)
        return ds.input

    def serialize_transaction(chain, tx):
        ds = BCDataStream.BCDataStream()
        chain.ds_serialize_transaction(ds, tx)
        return ds.input

    def ds_block_header_hash(chain, ds):
        return chain.block_header_hash(
            ds.input[ds.read_cursor : ds.read_cursor + 80])

    def transaction_hash(chain, binary_tx):
        return util.double_sha256(binary_tx)

    def merkle_hash(chain, hashes):
        return util.double_sha256(hashes)

    # Based on CBlock::BuildMerkleTree().
    def merkle_root(chain, hashes):
        while len(hashes) > 1:
            size = len(hashes)
            out = []
            for i in xrange(0, size, 2):
                i2 = min(i + 1, size - 1)
                out.append(chain.merkle_hash(hashes[i] + hashes[i2]))
            hashes = out
        return hashes and hashes[0]

    def parse_block_header(chain, header):
        return chain.ds_parse_block_header(util.str_to_ds(header))

    def parse_transaction(chain, binary_tx):
        return chain.ds_parse_transaction(util.str_to_ds(binary_tx))

    def is_coinbase_tx(chain, tx):
        return len(tx['txIn']) == 1 and tx['txIn'][0]['prevout_hash'] == chain.coinbase_prevout_hash

    coinbase_prevout_hash = util.NULL_HASH
    coinbase_prevout_n = 0xffffffff
    genesis_hash_prev = util.GENESIS_HASH_PREV

    def parse_txout_script(chain, script):
        """
        Return TYPE, DATA where the format of DATA depends on TYPE.

        * SCRIPT_TYPE_INVALID  - DATA is the raw script
        * SCRIPT_TYPE_UNKNOWN  - DATA is the decoded script
        * SCRIPT_TYPE_PUBKEY   - DATA is the binary public key
        * SCRIPT_TYPE_ADDRESS  - DATA is the binary public key hash
        * SCRIPT_TYPE_BURN     - DATA is None
        * SCRIPT_TYPE_MULTISIG - DATA is {"m":M, "pubkeys":list_of_pubkeys}
        * SCRIPT_TYPE_P2SH     - DATA is the binary script hash
        """
        if script is None:
            raise ValueError()
        try:
            decoded = [ x for x in deserialize.script_GetOp(script) ]
        except Exception:
            return SCRIPT_TYPE_INVALID, script
        return chain.parse_decoded_txout_script(decoded)

    def parse_decoded_txout_script(chain, decoded):
        if deserialize.match_decoded(decoded, SCRIPT_ADDRESS_TEMPLATE):
            pubkey_hash = decoded[2][1]
            if len(pubkey_hash) == PUBKEY_HASH_LENGTH:
                return SCRIPT_TYPE_ADDRESS, pubkey_hash

        elif deserialize.match_decoded(decoded, SCRIPT_PUBKEY_TEMPLATE):
            pubkey = decoded[0][1]
            return SCRIPT_TYPE_PUBKEY, pubkey

        elif deserialize.match_decoded(decoded, SCRIPT_P2SH_TEMPLATE):
            script_hash = decoded[1][1]
            assert len(script_hash) == PUBKEY_HASH_LENGTH
            return SCRIPT_TYPE_P2SH, script_hash

        elif deserialize.match_decoded(decoded, SCRIPT_BURN_TEMPLATE):
            return SCRIPT_TYPE_BURN, None

        elif len(decoded) >= 4 and decoded[-1][0] == opcodes.OP_CHECKMULTISIG:
            # cf. bitcoin/src/script.cpp:Solver
            n = decoded[-2][0] + 1 - opcodes.OP_1
            m = decoded[0][0] + 1 - opcodes.OP_1
            if 1 <= m <= n <= MAX_MULTISIG_KEYS and len(decoded) == 3 + n and \
                    all([ decoded[i][0] <= opcodes.OP_PUSHDATA4 for i in range(1, 1+n) ]):
                return SCRIPT_TYPE_MULTISIG, \
                    { "m": m, "pubkeys": [ decoded[i][1] for i in range(1, 1+n) ] }

        # Namecoin overrides this to accept name operations.
        return SCRIPT_TYPE_UNKNOWN, decoded

    def pubkey_hash(chain, pubkey):
        return util.pubkey_to_hash(pubkey)

    def script_hash(chain, script):
        return chain.pubkey_hash(script)

    datadir_conf_file_name = "bitcoin.conf"
    datadir_rpcport = 8332

class Sha256Chain(Chain):
    def block_header_hash(chain, header):
        return util.double_sha256(header)

class Bitcoin(Sha256Chain):
    def __init__(chain, **kwargs):
        chain.name = 'Bitcoin'
        chain.code3 = 'BTC'
        chain.address_version = '\x00'
        chain.script_addr_vers = '\x05'
        chain.magic = '\xf9\xbe\xb4\xd9'
        Chain.__init__(chain, **kwargs)

class Testnet(Sha256Chain):
    def __init__(chain, **kwargs):
        chain.name = 'Testnet'
        chain.code3 = 'BC0'
        chain.address_version = '\x6f'
        chain.script_addr_vers = '\xc4'
        chain.magic = '\xfa\xbf\xb5\xda'
        Chain.__init__(chain, **kwargs)

    # XXX
    #datadir_conf_file_name = "bitcoin.conf"
    #datadir_rpcport = 8332

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

class Namecoin(Sha256NmcAuxPowChain):
    def __init__(chain, **kwargs):
        chain.name = 'Namecoin'
        chain.code3 = 'NMC'
        chain.address_version = '\x34'
        chain.magic = '\xf9\xbe\xb4\xfe'
        Chain.__init__(chain, **kwargs)

    _drops = (opcodes.OP_NOP, opcodes.OP_DROP, opcodes.OP_2DROP)

    def parse_decoded_txout_script(chain, decoded):
        start = 0
        pushed = 0

        # Tolerate (but ignore for now) name operations.
        for i in xrange(len(decoded)):
            opcode = decoded[i][0]

            if decoded[i][1] is not None or \
                    opcode == opcodes.OP_0 or \
                    opcode == opcodes.OP_1NEGATE or \
                    (opcode >= opcodes.OP_1 and opcode <= opcodes.OP_16):
                pushed += 1
            elif opcode in chain._drops:
                to_drop = chain._drops.index(opcode)
                if pushed < to_drop:
                    break
                pushed -= to_drop
                start = i + 1
            else:
                return Chain.parse_decoded_txout_script(chain, decoded[start:])

        return SCRIPT_TYPE_UNKNOWN, decoded


    datadir_conf_file_name = "namecoin.conf"
    datadir_rpcport = 8336

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

class X11Chain(Chain):
    def block_header_hash(chain, header):
        import xcoin_hash
        return xcoin_hash.getPoWHash(header)

class X11PosChain(X11Chain, PpcPosChain):
    pass

class Hirocoin(X11Chain):
    def __init__(chain, **kwargs):
        chain.name = 'Hirocoin'
        chain.code3 = 'HIRO'
        chain.address_version = '\x28'
        chain.script_addr_vers = '\x05'
        chain.magic = '\xfe\xc4\xb9\xde'
        Chain.__init__(chain, **kwargs)

    datadir_conf_file_name = 'hirocoin.conf'
    datadir_rpcport = 9347
    datadir_p2pport = 9348

YAC_START_TIME = 1377557832

class ScryptJaneChain(Chain):
    def block_header_hash(chain, header):
        import yac_scrypt
        b = chain.parse_block_header(header)
        return yac_scrypt.getPoWHash(header, b['nTime'] + YAC_START_TIME - chain.start_time)

class Bitleu(ScryptJaneChain, PpcPosChain):
    def __init__(chain, **kwargs):
        chain.name = 'Bitleu'
        chain.code3 = 'BTL'
        chain.address_version = "\x30"
        chain.script_addr_vers = '\x1b'
        chain.magic = "\xd9\xe6\xe7\xe5"
        chain.decimals = 6
        Chain.__init__(chain, **kwargs)

    datadir_conf_file_name = "Bitleu.conf"
    datadir_rpcport = 7997
    start_time = 1394480376

class KeccakChain(Chain):
    def block_header_hash(chain, header):
        return util.sha3_256(header)

class Maxcoin(KeccakChain):
    def __init__(chain, **kwargs):
        chain.name = 'Maxcoin'
        chain.code3 = 'MAX'
        chain.address_version = '\x6e'
        chain.script_addr_vers = '\x70'
        chain.magic = "\xf9\xbe\xbb\xd2"
        Chain.__init__(chain, **kwargs)

    def transaction_hash(chain, binary_tx):
        return util.sha256(binary_tx)

    datadir_conf_file_name = 'maxcoin.conf'
    datadir_rpcport = 8669
