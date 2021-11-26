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

#
# Misc util routines
#
import os
import platform
import re
import hashlib
import json
from typing import Union
from urllib.request import urlopen
from Crypto.Hash import SHA256
from base58 import b58decode, b58encode
from .streams import BCDataStream
from .exceptions import JsonrpcMethodNotFound, JsonrpcException

try:
    import Crypto.Hash.RIPEMD as RIPEMD160
except ImportError:
    from . import ripemd_via_hashlib as RIPEMD160

# This function comes from bitcointools, bct-LICENSE.txt.
def determine_db_dir():

    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin/")
    if platform.system() == "Windows":
        return os.path.join(os.environ["APPDATA"], "Bitcoin")
    return os.path.expanduser("~/.bitcoin")


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(_bytes):
    return _bytes.encode("hex_codec")


# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(_bytes):
    _hex = _bytes.encode("hex_codec")
    if len(_hex) < 11:
        return _hex
    return _hex[0:4] + "..." + _hex[-4:]


NULL_HASH = b"\x00" * 32
GENESIS_HASH_PREV = NULL_HASH


def sha256(data):
    return SHA256.new(data).digest()


def double_sha256(data):
    return sha256(sha256(data))


def sha3_256(data):
    return hashlib.sha3_256(data).digest()


def pubkey_to_hash(pubkey):
    return RIPEMD160.new(SHA256.new(pubkey).digest()).digest()


def calculate_target(nBits):
    # cf. CBigNum::SetCompact in bignum.h
    shift = 8 * (((nBits >> 24) & 0xFF) - 3)
    bits = nBits & 0x7FFFFF
    sign = -1 if (nBits & 0x800000) else 1
    return sign * (bits << shift if shift >= 0 else bits >> -shift)


def target_to_difficulty(target):
    return ((1 << 224) - 1) * 1000 / (target + 1) / 1000.0


def calculate_difficulty(nBits):
    return target_to_difficulty(calculate_target(nBits))


def work_to_difficulty(work):
    return work * ((1 << 224) - 1) * 1000 / (1 << 256) / 1000.0


def target_to_work(target):
    # XXX will this round using the same rules as C++ Bitcoin?
    return int((1 << 256) / (target + 1))


def calculate_work(prev_work, nBits):
    if prev_work is None:
        return None
    return prev_work + target_to_work(calculate_target(nBits))


def work_to_target(work):
    return int((1 << 256) / work) - 1


def get_search_height(height):
    if height < 2:
        return None
    if height & 1:
        return height >> 1 if height & 2 else height - (height >> 2)
    bit = 2
    while (height & bit) == 0:
        bit <<= 1
    return height - bit


ADDRESS_RE = re.compile("[1-9A-HJ-NP-Za-km-z]{26,}\\Z")


def possible_address(string):
    return ADDRESS_RE.match(string)


def hash_to_address(version, _hash):
    version_hash = version + _hash
    return b58encode(version_hash + double_sha256(version_hash)[:4])


def decode_check_address(address):
    if possible_address(address):
        version, _hash = decode_address(address)
        if hash_to_address(version, _hash) == address:
            return version, _hash
    return None, None


def decode_address(addr):
    _bytes = b58decode(addr)
    if len(_bytes) < 25:
        _bytes = ("\0" * (25 - len(_bytes))) + _bytes
    return _bytes[:-24], _bytes[-24:-4]


def jsonrpc(url, method, *params):
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
