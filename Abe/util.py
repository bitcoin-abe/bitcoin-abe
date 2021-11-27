# Copyright(C) 2011,2012,2013,2014 by Abe developers.
# Copyright (c) 2010 Gavin Andresen

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


"""Misc util routines"""

import os
import platform
import re
import hashlib
import json
from typing import Match, Union
from urllib.request import urlopen
from Crypto.Hash import SHA256, RIPEMD160
from base58 import b58decode, b58encode
from .streams import BCDataStream
from .exceptions import JsonrpcMethodNotFound, JsonrpcException

NULL_HASH = b"\x00" * 32
GENESIS_HASH_PREV = NULL_HASH
ADDRESS_RE = re.compile("[1-9A-HJ-NP-Za-km-z]{26,}\\Z")

# This function comes from bitcointools, bct-LICENSE.txt.
def determine_db_dir() -> str:
    """Search for the default Bitcoin datadir"""
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin/")
    if platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "Bitcoin")
    return os.path.expanduser("~/.bitcoin")


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(_bytes: Union[bytes, bytearray]) -> str:
    """Returns the full hexadecimal string of a binary input"""
    return b2hex(_bytes)


# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(_bytes: Union[bytes, bytearray]) -> str:
    """Returns the truncated hexadecimal string of a binary input"""
    _hex = b2hex(_bytes)
    if len(_hex) < 11:
        return _hex
    return _hex[0:4] + "..." + _hex[-4:]


def sha256(data: Union[bytes, bytearray, memoryview, None]) -> bytes:
    return SHA256.new(data).digest()


def double_sha256(data: Union[bytes, bytearray, memoryview, None]) -> bytes:
    return sha256(sha256(data))


def sha3_256(data: Union[bytes, bytearray, memoryview, None]) -> bytes:
    return hashlib.sha3_256(data).digest()


def pubkey_to_hash(pubkey: Union[bytes, bytearray, memoryview, None]) -> bytes:
    return RIPEMD160.new(SHA256.new(pubkey).digest()).digest()


def calculate_target(nBits: int) -> int:
    # cf. CBigNum::SetCompact in bignum.h
    shift = 8 * (((nBits >> 24) & 0xFF) - 3)
    bits = nBits & 0x7FFFFF
    sign = -1 if (nBits & 0x800000) else 1
    return sign * (bits << shift if shift >= 0 else bits >> -shift)


# XXX need to get the type of target whether int of float
def target_to_difficulty(target) -> float:
    return ((1 << 224) - 1) * 1000 / (target + 1) / 1000.0


def calculate_difficulty(nBits) -> float:
    return target_to_difficulty(calculate_target(nBits))


def work_to_difficulty(work: int) -> float:
    return work * ((1 << 224) - 1) * 1000 / (1 << 256) / 1000.0


def target_to_work(target) -> int:
    # XXX will this round using the same rules as C++ Bitcoin?
    return int((1 << 256) / (target + 1))


def calculate_work(prev_work: Union[int, None], nBits: int) -> Union[int, None]:
    if prev_work is None:
        return None
    return prev_work + target_to_work(calculate_target(nBits))


def work_to_target(work: int) -> int:
    return int((1 << 256) / work) - 1


def get_search_height(height: int) -> Union[int, None]:
    if height < 2:
        return None
    if height & 1:
        return height >> 1 if height & 2 else height - (height >> 2)
    bit = 2
    while (height & bit) == 0:
        bit <<= 1
    return height - bit


def possible_address(string: Union[str, bytes, bytearray]) -> Union[Match[str], None]:
    """Determine if a string matches the regex format of an address.
    This method only accepts b58encoded data"""
    if not isinstance(string, bytearray):
        string = bytes(string)
    string = str(string, "utf-8")
    return ADDRESS_RE.match(string)


def hash_to_address(
    version: bytes, _hash: Union[str, bytes, bytearray, memoryview]
) -> bytes:
    if isinstance(_hash, str):
        _hash = hex2b(_hash)
    version_hash = bytearray(version) + bytearray(_hash)
    return b58encode(version_hash + double_sha256(version_hash)[:4])


def decode_address(address: Union[bytes, str]) -> tuple[bytes, bytes]:
    _bytes = b58decode(address)
    if len(_bytes) < 25:
        _bytes = ("\0" * (25 - len(_bytes))) + _bytes
    return _bytes[:-24], _bytes[-24:-4]


def decode_check_address(
    address: Union[str, bytes]
) -> Union[tuple[bytes, bytes], tuple[None, None]]:
    address = b58encode(address)
    if possible_address(address):
        version, _hash = decode_address(address)
        if hash_to_address(version, _hash) == address:
            return version, _hash
    return None, None


# XXX not sure type of method
def jsonrpc(url: str, method, *params) -> str:
    postdata = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": "x"}
    )
    respdata = urlopen(url, postdata).read()
    resp = json.loads(respdata)
    if resp.get("error") is not None:
        if resp["error"]["code"] == -32601:
            raise JsonrpcMethodNotFound(resp["error"], method, params)
        raise JsonrpcException(resp["error"], method, params)
    return resp["result"]


def str_to_ds(data: str) -> BCDataStream:
    data_stream = BCDataStream()
    data_stream.write(data)
    return data_stream


# Abstract hex-binary conversions for Python 3.
def hex2b(data: str) -> bytes:
    """Convert a hexadecimal string into binary data"""
    return bytes.fromhex(data)


def b2hex(data: Union[bytes, bytearray]) -> str:
    """Convert raw binary data into a hexadecimal string"""
    if isinstance(data, bytearray):
        data = bytes(data)
    return bytes.hex(data)
