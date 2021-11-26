# Copyright(C) 2014 by Abe developers.

"""datagen.py: test data generation"""

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

from random import Random
import struct
from typing import Any, Union
from Abe import Chain, util
from Abe.util import hex2b
from Abe.deserialize import opcodes
from Abe.streams import BCDataStream


class Gen:
    def __init__(self, rng=1, chain=None, **kwargs):
        if not hasattr(rng, "randrange"):
            rng = Random(rng)
        if chain is None:
            chain = Chain.create("Testnet")

        self._rng = rng
        self.chain = chain
        self.blocks = []

        for attr, val in kwargs.items():
            setattr(self, attr, val)

    def random_bytes(self, num_bytes):
        """Generate random bytes of length num_bytes"""
        return "".join(chr(self._rng.randrange(256)) for _ in range(num_bytes))

    def random_addr_hash(self):
        """Generate a random address hash"""
        return self.random_bytes(20)

    def encode_script(self, *script_data) -> bytearray:
        """Encode OP_CODES and script contents into bytes.
        Do not pass into here a hex string unless if the hex string is to be utf-8 encoded.
        If hexadecimal data is to be kept unchanged it needs to be passed in as bytes

        OP_CODES must be passed in as int() using opcodes.OP_* format
        """
        data_stream = BCDataStream()
        for val in script_data:
            if isinstance(val, int):
                data_stream.write(val.to_bytes((val.bit_length() + 7) // 8, "little"))
            elif isinstance(val, str) | isinstance(val, bytes):
                data_stream.write_string(val)
            else:
                raise ValueError(val)
        return data_stream.input

    def opcode(self, num: int) -> bytes:
        """
        Returns a binary representation of the OP_CODE using an integer input:
            num = -1    OP_RESERVED

            num = 0     OP_0

            1 ≤ num ≤16 OP_1-OP_16

            num > 16    OP_NOP - OP_NOP10

            num < -1    256 + num
        """
        if num == 0:
            return opcodes.OP_0  # .to_bytes(1, byteorder="little")
        if num == -1 or 1 <= num <= 16:
            val = num + opcodes.OP_1 - 1
            return val  # .to_bytes(1, byteorder="little")
        if num > 0:
            return num  # .to_bytes(1, byteorder="little")
        return 256 + num  # .to_bytes(1, byteorder="little")

    def address_scriptPubKey(self, hash_):
        return self.encode_script(
            opcodes.OP_DUP,
            opcodes.OP_HASH160,
            hash_,
            opcodes.OP_EQUALVERIFY,
            opcodes.OP_CHECKSIG,
        )

    def pubkey_scriptPubKey(self, pubkey):
        return self.encode_script(pubkey, opcodes.OP_CHECKSIG)

    def multisig_scriptPubKey(self, m: int, pubkeys: list[Union[bytes, str]]) -> bytes:
        ops = (
            [self.opcode(m)]
            + pubkeys
            + [self.opcode(len(pubkeys)), opcodes.OP_CHECKMULTISIG]
        )
        return self.encode_script(*ops)

    def p2sh_scriptPubKey(self, hash_):
        return self.encode_script(opcodes.OP_HASH160, hash_, opcodes.OP_EQUAL)

    def txin(self, **kwargs):
        txin = {"sequence": 0xFFFFFFFF, "pos": 0}
        txin.update(kwargs)
        if "prevout" in txin:
            txin["prevout_hash"] = txin["prevout"]["hash"]
            txin["prevout_n"] = txin["prevout"]["pos"]
        return txin

    def coinbase_txin(self, **kwargs) -> dict[str, Any]:
        chain = self.chain
        args = {
            "prevout_hash": chain.coinbase_prevout_hash,
            "prevout_n": chain.coinbase_prevout_n,
            "scriptSig": hex2b("04ffff001d0101"),
        }
        args.update(kwargs)
        return self.txin(**args)

    def txout(self, **kwargs) -> dict[str, Any]:
        txout = {"value": 1, "pos": 0}
        txout.update(kwargs)

        if "scriptPubKey" in txout:
            pass
        elif "multisig" in txout:
            txout["scriptPubKey"] = self.multisig_scriptPubKey(
                txout["multisig"]["m"], txout["multisig"]["pubkeys"]
            )
        elif "pubkey" in txout:
            txout["scriptPubKey"] = self.pubkey_scriptPubKey(txout["pubkey"])
        elif "addr" in txout:
            version, hash_ = util.decode_check_address(txout["addr"])
            if version == self.chain.address_version:
                txout["scriptPubKey"] = self.address_scriptPubKey(hash_)
            elif version == self.chain.script_addr_vers:
                txout["scriptPubKey"] = self.p2sh_scriptPubKey(hash_)
            else:
                raise ValueError(
                    f"Invalid address version {version} not in \
                        ({self.chain.address_version}, {self.chain.script_addr_vers})"
                )
        else:
            txout["scriptPubKey"] = self.address_scriptPubKey(self.random_addr_hash())

        return txout

    def tx(
        self,
        txIn: dict[str, Any],
        txOut: dict[str, Any],
        version: int = 1,
        lockTime: int = 0,
    ) -> dict[str, Any]:
        """Generate a dict of the data in a tx"""
        chain = self.chain

        def parse_txin(i, arg):
            arg["pos"] = i
            return self.txin(**arg)

        def parse_txout(i, arg):
            arg["pos"] = i
            return self.txout(**arg)

        tx = {
            "version": version,
            "txIn": [parse_txin(i, arg) for i, arg in enumerate(txIn)],
            "txOut": [parse_txout(i, arg) for i, arg in enumerate(txOut)],
            "lockTime": lockTime,
        }
        tx["__data__"] = chain.serialize_transaction(tx)
        tx["hash"] = chain.transaction_hash(tx["__data__"])

        for txout in tx["txOut"]:
            txout["hash"] = tx["hash"]

        return tx

    def coinbase(
        self, txOut: dict[str, Any] = None, value: int = 50e8, **kwargs
    ) -> dict[str, Any]:
        """Generate the coinbase transaction."""
        txIn = [self.coinbase_txin(**kwargs)]
        kwargs.pop("scriptSig")
        if txOut is None:
            txOut = [self.txout(value=value)]
        return self.tx(txIn, txOut, **kwargs)

    def block(
        self,
        prev=None,
        transactions=None,
        version=1,
        nTime=1231006506,
        nBits=0x1D00FFFF,
        nNonce=253,
    ):
        chain = self.chain

        if prev is None:
            prev = chain.genesis_hash_prev
        elif isinstance(prev, dict):
            prev = prev["hash"]

        if transactions is None:
            transactions = [self.coinbase()]

        block = {
            "version": version,
            "hashPrev": prev,
            "hashMerkleRoot": chain.merkle_root([tx["hash"] for tx in transactions]),
            "nTime": nTime,
            "nBits": nBits,
            "nNonce": nNonce,
            "transactions": transactions,
        }
        block["hash"] = chain.block_header_hash(chain.serialize_block_header(block))

        return block

    def save_blkfile(self, blkfile, blocks):
        with open(blkfile, "wb") as f:
            for bobj in blocks:
                f.write(self.chain.magic)
                bstr = self.chain.serialize_block(bobj)
                f.write(struct.pack("<i", len(bstr)))  # pylint: disable=no-member
                f.write(bstr)
