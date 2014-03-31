# Copyright(C) 2014 by Abe developers.

# datagen.py: test data generation

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

import Abe.Chain
import Abe.BCDataStream
import Abe.util

from Abe.deserialize import opcodes

class Gen(object):
    def __init__(gen, rng=1, chain=None, **kwargs):
        if not hasattr(rng, 'randrange'):
            import random
            rng = random.Random(rng)
        if chain is None:
            chain = Abe.Chain.create("Testnet")

        gen._rng = rng
        gen.chain = chain

        for attr, val in kwargs.items():
            setattr(gen, attr, val)

    def random_bytes(gen, num_bytes):
        return ''.join(chr(gen._rng.randrange(256)) for _ in xrange(num_bytes))

    def random_addr_hash(gen):
        return gen.random_bytes(20)

    def encode_script(gen, *ops):
        ds = Abe.BCDataStream.BCDataStream()
        for op in ops:
            if isinstance(op, int):
                ds.write(chr(op))
            elif isinstance(op, str):
                ds.write_string(op)
            else:
                raise ValueError(op)
        return ds.input

    def op(gen, d):
        if isinstance(d, int):
            if d == 0:
                return opcodes.OP_0
            if d == -1 or 1 <= d <= 16:
                return d + opcodes.OP_1 - 1
            # Hmm, maybe time to switch to Python 3 with int.from_bytes?
            h = "00%x" % (d if d >= 0 else -1-d)
            if len(h) % 2:
                h = h[1:]
            elif h[2] < '8':
                h = h[2:]
            if d < 0:
                import string
                h = h.translate(string.maketrans('0123456789abcdef', 'fedcba9876543210'))
            return h.decode('hex')
        raise ValueError(n)

    def address_scriptPubKey(gen, hash):
        return gen.encode_script(opcodes.OP_DUP, opcodes.OP_HASH160, hash, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG)

    def pubkey_scriptPubKey(gen, pubkey):
        return gen.encode_script(pubkey, opcodes.OP_CHECKSIG)

    def multisig_scriptPubKey(gen, m, pubkeys):
        ops = [ gen.op(m) ] + pubkeys + [ gen.op(len(pubkeys)), opcodes.OP_CHECKMULTISIG ]
        return gen.encode_script(*ops)

    def p2sh_scriptPubKey(gen, hash):
        return gen.encode_script(opcodes.OP_HASH160, hash, opcodes.OP_EQUAL)

    def txin(gen, **kwargs):
        txin = { 'sequence': 0xffffffff, 'pos': 0 }
        txin.update(kwargs)
        if 'prevout' in txin:
            txin['prevout_hash'] = txin['prevout']['hash']
            txin['prevout_n'] = txin['prevout']['pos']
        return txin

    def coinbase_txin(gen, **kwargs):
        chain = gen.chain
        args = {
            'prevout_hash': chain.coinbase_prevout_hash,
            'prevout_n':    chain.coinbase_prevout_n,
            'scriptSig': '04ffff001d0101'.decode('hex'),
            }
        args.update(kwargs)
        return gen.txin(**args)

    def txout(gen, **kwargs):
        txout = { 'value': 1, 'pos': 0 }
        txout.update(kwargs)

        if 'scriptPubKey' in txout:
            pass
        elif 'multisig' in txout:
            txout['scriptPubKey'] = gen.multisig_scriptPubKey(txout['multisig']['m'], txout['multisig']['pubkeys'])
        elif 'pubkey' in txout:
            txout['scriptPubKey'] = gen.pubkey_scriptPubKey(txout['pubkey'])
        elif 'addr' in txout:
            version, hash = Abe.util.decode_check_address(txout['addr'])
            if version == gen.chain.address_version:
                txout['scriptPubKey'] = gen.address_scriptPubKey(hash)
            elif version == gen.chain.script_addr_vers:
                txout['scriptPubKey'] = gen.p2sh_scriptPubKey(hash)
            else:
                raise ValueError('Invalid address version %r not in (%r, %r)' % (version, gen.chain.address_version, gen.chain.script_addr_vers))
        else:
            txout['scriptPubKey'] = gen.address_scriptPubKey(gen.random_addr_hash())

        return txout

    def tx(gen, txIn, txOut, version=1, lockTime=0, **kwargs):
        chain = gen.chain

        def parse_txin(i, arg):
            arg['pos'] = i
            return gen.txin(**arg)

        def parse_txout(i, arg):
            arg['pos'] = i
            return gen.txout(**arg)

        tx = {
            'version': version,
            'txIn': [parse_txin(i, arg) for i, arg in enumerate(txIn)],
            'txOut': [parse_txout(i, arg) for i, arg in enumerate(txOut)],
            'lockTime': lockTime,
            }
        tx['__data__'] = chain.serialize_transaction(tx)
        tx['hash'] = chain.transaction_hash(tx['__data__'])

        for txout in tx['txOut']:
            txout['hash'] = tx['hash']

        return tx

    def coinbase(gen, txOut=None, value=50e8, **kwargs):
        if txOut is None:
            txOut = [ gen.txout(value=value) ]
        return gen.tx([ gen.coinbase_txin(**kwargs) ], txOut, **kwargs)

    def block(gen, prev=None, transactions=None, version=1, nTime=1231006506, nBits=0x1d00ffff, nNonce=253):
        chain = gen.chain

        if prev is None:
            prev = chain.genesis_hash_prev
        elif isinstance(prev, dict):
            prev = prev['hash']

        if transactions is None:
            transactions = [gen.coinbase()]

        block = {
            'version':  version,
            'hashPrev': prev,
            'hashMerkleRoot': chain.merkle_root([ tx['hash'] for tx in transactions ]),
            'nTime':    nTime,
            'nBits':    nBits,
            'nNonce':   nNonce,
            'transactions': transactions,
            }
        block['hash'] = chain.block_header_hash(chain.serialize_block_header(block))

        return block

    def save_blkfile(gen, blkfile, blocks):
        import struct
        with open(blkfile, 'wb') as f:
            for bobj in blocks:
                f.write(gen.chain.magic)
                bstr = gen.chain.serialize_block(bobj)
                f.write(struct.pack('<i', len(bstr)))
                f.write(bstr)
