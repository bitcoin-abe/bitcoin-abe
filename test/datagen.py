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

def encode_script(*ops):
    ds = Abe.BCDataStream.BCDataStream()
    for op in ops:
        if isinstance(op, int):
            ds.write(chr(op))
        elif isinstance(op, str):
            ds.write_string(op)
        else:
            ds.write(op)
    return ds.input

class Gen(object):
    def __init__(gen, rng=None, chain=None):
        if rng is None:
            import random
            rng = random.Random(1)
        if chain is None:
            chain = Abe.Chain.create("Testnet")

        gen._rng = rng
        gen.chain = chain

    def random_bytes(gen, num_bytes):
        return ''.join(chr(gen._rng.randrange(256)) for _ in xrange(num_bytes))

    def random_addr_hash(gen):
        return gen.random_bytes(20)

    def address_scriptPubKey(gen, hash):
        return encode_script(opcodes.OP_DUP, opcodes.OP_HASH160, hash, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG)

    def pubkey_scriptPubKey(gen, pubkey):
        return encode_script(pubkey, opcodes.OP_CHECKSIG)

    def multisig_scriptPubKey(gen, m, addrs):
        ops = [m]

    def p2sh_scriptPubKey(gen, hash):
        return encode_script(opcodes.OP_HASH160, hash, opcodes.OP_EQUAL)

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
                raise ValueError('Invalid address version %r' % version)
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

    def coinbase(gen, txOut=None, **kwargs):
        if txOut is None:
            txOut = [ gen.txout(value=50*10**8) ]  # 50BTC
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
