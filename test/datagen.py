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
from typing import Any, Optional, TypedDict, Union, List, Dict
from Abe import Chain, util
from Abe.Chain import BaseChain

# from Abe.data_store import DataStore
from Abe.merkle import Merkle
from Abe.streams import BCDataStream
from Abe.typing import Block, BlockHeader, TxOut, TxIn, Witness, opcodes
from Abe.util import b2hex, hex2b

# from .db import DataBasetype

# pylint: disable=invalid-name


class MultiSig(TypedDict, total=False):
    """Multisig Data Structure"""

    m: int
    pubkeys: List[bytes]


class TxOutTest(TxOut, total=False):
    """Output Transaction Testing Data Structure"""

    hash: bytes
    pos: int
    multisig: Optional[MultiSig]
    pubkey: bytes
    addr: bytes


class TxInTest(TxIn, total=False):
    """TxIn Data Structure"""

    pos: int


class TransactionTest(TypedDict, total=False):
    """Testing Transaction Data Structure"""

    version: int
    nTime: Optional[bytes]  # This is for some alt.
    marker: Optional[bytes]  # SegWit marker
    flag: Optional[bytes]  # SegWit flag
    txIn: List[TxIn]
    txOut: List[TxOutTest]
    witness: Optional[List[Witness]]  # segregated witness
    lockTime: int
    __data__: Union[bytearray, memoryview, None]
    hash: bytes


class BlockTest(BlockHeader, total=False):
    """Testing Block Dictionary Type"""

    transactions: List[TransactionTest]
    hash: bytes


class Gen:
    """Data Factory for Unit Testing"""

    def __init__(
        self,
        chain: BaseChain = None,
        # data_base: DataBasetype = None,
        seed: Any = None,
        **kwargs,
    ):
        if chain is None:
            chain = Chain.create("Testnet")

        if seed is None:
            seed = b"This is the default seed."

        self._random = Random(seed)
        self.chain = chain
        self.blocks: List[BlockTest] = []
        # if data_base is not None:
        #     db_args = data_base.get_connect_args()
        # self.store = DataStore(db_args)

        for attr, val in kwargs.items():
            setattr(self, attr, val)

    def random_bytes(self, num_bytes: int) -> bytes:
        """Generate random bytes of length num_bytes"""
        rand_bytes: bytes = self._random.randbytes(num_bytes)  # type: ignore
        return rand_bytes

    def random_addr_hash(self):
        """Generate a random address hash"""
        return self.random_bytes(20)

    def encode_script(self, *script_data) -> Union[bytearray, memoryview, None]:
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

    def opcode(self, num: int) -> int:
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

    def address_scriptPubKey(self, _hash: bytes) -> Union[bytearray, memoryview, None]:
        """Generate ScriptPubKEy from address hash"""
        return self.encode_script(
            opcodes.OP_DUP,
            opcodes.OP_HASH160,
            _hash,
            opcodes.OP_EQUALVERIFY,
            opcodes.OP_CHECKSIG,
        )

    def pubkey_scriptPubKey(
        self, pubkey: Union[str, bytes]
    ) -> Union[bytearray, memoryview, None]:
        """Just encode the PubKey in the ScriptPubKey"""
        return self.encode_script(pubkey, opcodes.OP_CHECKSIG)

    def multisig_scriptPubKey(self, m: int, pubkeys: List[bytes]) -> bytes:
        """Multisig ScriptPubKey"""
        ops: List[Any] = [self.opcode(m)]
        ops += pubkeys
        ops += [self.opcode(len(pubkeys)), opcodes.OP_CHECKMULTISIG]
        script = self.encode_script(*tuple(ops))
        if script is None:
            raise IOError
        return bytes(script)

    def p2sh_scriptPubKey(self, hash_: bytes) -> Union[bytearray, memoryview, None]:
        """SEGWIT address type ScriptPubKey"""
        return self.encode_script(opcodes.OP_HASH160, hash_, opcodes.OP_EQUAL)

    def txin(self, **kwargs) -> TxInTest:
        """utx_in"""
        txin: TxInTest = {"sequence": 0xFFFFFFFF, "pos": 0}
        txin.update(kwargs)  # type: ignore
        return txin

    def coinbase_txin(self, **kwargs) -> TxInTest:
        """Coinbase tx input"""
        chain = self.chain
        args = {
            "prevout_hash": chain.coinbase_prevout_hash,
            "prevout_n": chain.coinbase_prevout_n,
            "scriptSig": hex2b("04ffff001d0101"),
        }
        args.update(kwargs)
        return self.txin(**args)

    def txout(self, **kwargs) -> TxOutTest:
        """utxo"""
        txout: TxOutTest = {"value": 1, "pos": 0}
        txout.update(kwargs)  # type: ignore

        if "scriptPubKey" in txout:
            pass
        elif "multisig" in txout and txout["multisig"] is not None:
            txout["scriptPubKey"] = self.multisig_scriptPubKey(
                txout["multisig"]["m"], txout["multisig"]["pubkeys"]
            )
        elif "pubkey" in txout:
            pubkey = self.pubkey_scriptPubKey(txout["pubkey"])
            if pubkey is not None:
                txout["scriptPubKey"] = bytes(pubkey)
        elif "addr" in txout:
            version, hash_ = util.decode_check_address(txout["addr"])
            if version == self.chain.address_version and hash_ is not None:
                address = self.address_scriptPubKey(hash_)
                if address is not None:
                    txout["scriptPubKey"] = bytes(address)
            elif version == self.chain.script_addr_vers and hash_ is not None:
                p2sh = self.p2sh_scriptPubKey(hash_)
                if p2sh is not None:
                    txout["scriptPubKey"] = bytes(p2sh)
            else:
                if version is None:
                    b_version = "(None)"
                else:
                    b_version = b2hex(version)
                raise ValueError(
                    f"Invalid address version {b_version} not in "
                    f"({b2hex(self.chain.address_version)}, "
                    f"{b2hex(self.chain.script_addr_vers)})"
                )
        else:
            rand_address = self.address_scriptPubKey(self.random_addr_hash())
            if rand_address is not None:
                txout["scriptPubKey"] = bytes(rand_address)

        return txout

    def tx(
        self,
        txIn: List[TxInTest],
        txOut: List[TxOutTest],
        version: int = 1,
        lockTime: int = 0,
    ) -> TransactionTest:
        """Generate a dict of the data in a tx"""
        chain = self.chain

        def parse_txin(i, arg):
            arg["pos"] = i
            return self.txin(**arg)

        def parse_txout(i, arg):
            arg["pos"] = i
            return self.txout(**arg)

        tx: TransactionTest = {
            "version": version,
            "txIn": [parse_txin(i, arg) for i, arg in enumerate(txIn)],
            "txOut": [parse_txout(i, arg) for i, arg in enumerate(txOut)],
            "lockTime": lockTime,
        }
        tx["__data__"] = chain.serialize_transaction(tx)  # type: ignore
        if tx["__data__"] is not None:
            for txout in tx["txOut"]:
                txout["hash"] = util.transaction_hash(tx["__data__"])

        return tx

    def coinbase(
        self, txOut: List[TxOutTest] = None, value: int = int(50e8), **kwargs
    ) -> TransactionTest:
        """Generate the coinbase transaction."""
        txIn = [self.coinbase_txin(**kwargs)]
        if "scriptSig" in kwargs:
            kwargs.pop("scriptSig")
        if txOut is None:
            txOut = [self.txout(value=value)]
        return self.tx(txIn, txOut, **kwargs)

    def block(
        self,
        prev: bytes = None,
        transactions: List[TransactionTest] = None,
        version: int = 1,
        nTime: int = 1231006506,
        nBits: int = 0x1D00FFFF,
        nNonce: int = 253,
    ) -> BlockTest:
        """Create a block dictionary"""
        chain = self.chain

        if prev is None:
            prev = chain.genesis_hash_prev
        elif isinstance(prev, Dict):
            prev = prev["hash"]

        if transactions is None:
            transactions = [self.coinbase()]
        merkle_root_hash = Merkle([tx["hash"] for tx in transactions]).root()
        block: Block = {
            "version": version,
            "hashPrev": prev,
            "hashMerkleRoot": merkle_root_hash,
            "nTime": nTime,
            "nBits": nBits,
            "nNonce": nNonce,
        }
        header = chain.serialize_block_header(block)  # type: ignore
        if header is not None:
            block["__header__"] = header
        block_test: BlockTest = {}
        for key, value in block.items():
            block_test[key] = value  # type: ignore
        if block_test["__header__"] is not None:
            block_test["hash"] = util.block_header_hash(block_test["__header__"])

        return block_test

    def save_blkfile(self, blkfile: str, blocks: List[BlockTest]) -> None:
        """Save the temporary blockfile"""
        with open(blkfile, "wb") as file:
            for block_obj in blocks:
                file.write(self.chain.magic)
                block: Block = {}
                for key, _ in block.items():
                    block[key] = block_obj[key]  # type: ignore
                bstr = self.chain.serialize_block(block)
                if bstr is not None:
                    file.write(
                        struct.pack("<i", len(bstr))  # pylint: disable=no-member
                    )
                    file.write(bstr)
            file.close()
