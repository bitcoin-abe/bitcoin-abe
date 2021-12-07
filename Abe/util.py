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
from typing import List, Any, Optional, Tuple, Union
from urllib.request import (
    HTTPPasswordMgrWithDefaultRealm,
    HTTPBasicAuthHandler,
    build_opener,
    install_opener,
    urlopen,
)
from Crypto.Hash import SHA256, RIPEMD160
from base58 import b58decode, b58encode


NULL_HASH = b"\x00" * 32
GENESIS_HASH_PREV = NULL_HASH
ADDRESS_RE = re.compile("[1-9A-HJ-NP-Za-km-z]{26,}\\Z")


class Memoize:
    """Memoization wrapper to create a class"""

    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args, **kwargs):
        return self.cache.setdefault(args, self.func(*args, **kwargs))


class JsonrpcException(Exception):
    """JSON RPC exceptions"""

    def __init__(self, error, method, params):
        Exception.__init__(self)
        self.code = error["code"]
        self.message = error["message"]
        self.data = error.get("data")
        self.method = method
        self.params = params

    def __str__(self):
        return self.method + ": " + self.message + " (code " + str(self.code) + ")"


class JsonrpcMethodNotFound(JsonrpcException):
    """No JSON RPC Method Found"""


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


#####################
# Hashing Functions #
#####################
def sha256(data: Union[bytes, bytearray, memoryview, None]) -> bytes:
    """sha256"""
    return SHA256.new(data).digest()


def double_sha256(data: Union[bytes, bytearray, memoryview, None]) -> bytes:
    """double_sha256"""
    return bytes(sha256(sha256(data)))


def sha3_256(data: Union[bytes, bytearray, memoryview, None]) -> bytes:
    """sha3_256"""
    if data is None:
        return b""
    return hashlib.sha3_256(data).digest()


def pubkey_to_hash(pubkey: Union[bytes, bytearray, memoryview, None]) -> bytes:
    """pubkey_to_hash"""
    return RIPEMD160.new(SHA256.new(pubkey).digest()).digest()


def script_to_hash(script: Union[bytes, bytearray, memoryview, None]) -> bytes:
    """script_to_hash"""
    return pubkey_to_hash(script)


# def transaction_hash(binary_tx: bytes) -> bytes:
#     """transaction_hash"""
#     return bytes(double_sha256(binary_tx))


# def witness_hash(binary_tx: bytes) -> bytes:
#     """witness_hash"""
#     return double_sha256(binary_tx)


# def block_header_hash(header: Union[bytes, bytearray, memoryview, None]) -> bytes:
#     """Provides the double SHA256 hash of the blockheader"""
#     return double_sha256(header)


def SHA256D64(hashes: List[bytes]) -> List[bytes]:  # pylint: disable=invalid-name
    """Concatenates an even list of hashes into a list of hashes of half the original length.
    Note: This is named after a similar and far more complete function in crypto/sha256.h

    Args:
        hashes (List[bytes]): An even length list of hashes.

    Raises:
        IndexError: if the list is not even

    Returns:
        List[bytes]: A list of new hashes half the original length
    """

    size = len(hashes)

    if size & 1:
        raise IndexError("Only an even length list can be passed.")

    _hashes = []

    for i in range(0, size, 2):
        j = i + 1
        concat_bytes = bytearray(hashes[i]) + bytearray(hashes[j])
        _hashes.append(double_sha256(concat_bytes))
    hashes = _hashes
    return hashes


#################################
# Difficulty and Work Functions #
#################################
def calculate_target(nBits: int) -> int:  # pylint: disable=invalid-name
    """calculate_target"""
    # cf. CBigNum::SetCompact in bignum.h
    shift = 8 * (((nBits >> 24) & 0xFF) - 3)
    bits = nBits & 0x7FFFFF
    sign = -1 if (nBits & 0x800000) else 1
    return sign * (bits << shift if shift >= 0 else bits >> -shift)


def target_to_difficulty(target: int) -> float:
    """target_to_difficulty"""
    value: float = ((1 << 224) - 1) * 1000 / (target + 1) / 1000.0
    return value


def calculate_difficulty(nBits) -> float:  # pylint: disable=invalid-name
    """calculate_difficulty"""
    return target_to_difficulty(calculate_target(nBits))


def work_to_difficulty(work: int) -> float:
    """work_to_difficulty"""
    return work * ((1 << 224) - 1) * 1000 / (1 << 256) / 1000.0


def target_to_work(target) -> int:
    """target_to_work"""
    # XXX will this round using the same rules as C++ Bitcoin?
    return int((1 << 256) / (target + 1))


def calculate_work(
    prev_work: Union[int, None], nBits: int  # pylint: disable=invalid-name
) -> Optional[int]:
    """calculate_work"""
    if prev_work is None:
        return None
    return prev_work + target_to_work(calculate_target(nBits))


def work_to_target(work: int) -> int:
    """work_to_target"""
    return int((1 << 256) / work) - 1


###########################
# Block and Address Tools #
###########################
def get_search_height(height: int) -> Optional[int]:
    """get_search_height"""
    if height < 2:
        return None
    if height & 1:
        return height >> 1 if height & 2 else height - (height >> 2)
    bit = 2
    while (height & bit) == 0:
        bit <<= 1
    return height - bit


def possible_address(string: Union[str, bytes]) -> bool:
    """Determine if a string matches the regex format of an address.
    This method only accepts b58encoded data"""
    if isinstance(string, bytes):
        string = str(string, "utf-8")
    return bool(ADDRESS_RE.match(string))


def hash_to_address(
    version: bytes, _hash: Union[str, bytes, bytearray, memoryview]
) -> bytes:
    """hash_to_address"""
    if isinstance(_hash, str):
        _hash = hex2b(_hash)
    version_hash = bytearray(version) + bytearray(_hash)
    _bytes = bytes(version_hash + double_sha256(version_hash)[:4])
    return b58encode(_bytes)


def decode_address(address: Union[str, bytes]) -> Tuple[bytes, bytes]:
    """decode_address"""
    decoded = bytearray(b58decode(address))
    if len(decoded) < 25:
        decoded = bytearray(b"\0" * (25 - len(decoded))) + decoded
    return bytes(decoded[:-24]), bytes(decoded[-24:-4])


def decode_check_address(
    address: Union[str, bytes]
) -> Union[Tuple[bytes, bytes], Tuple[None, None]]:
    """decode_check_address"""
    if isinstance(address, str):
        address = bytes(address, "utf-8")
    if possible_address(address):
        version, _hash = decode_address(address)
        if hash_to_address(version, _hash) == address:
            return version, _hash
    return None, None


##############################################
# Data Conversion and Manipulation Functions #
##############################################
def install_rpcopener(url: str, user: str, password: str) -> None:
    """Reconfigure urlopen to open the rpc connection with BasicAuth"""

    # https://docs.python.org/3.9/howto/urllib2.html#id5
    password_mgr = HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, user, password)
    handler = HTTPBasicAuthHandler(password_mgr)
    opener = build_opener(handler)
    install_opener(opener)


def jsonrpc(url: str, method: str, *params) -> Any:
    """jsonrpc"""
    postdata = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": "x"}
    )

    with urlopen(url, data=bytes(postdata, "utf-8")) as response:
        resp = json.loads(response.read())
    if resp["error"] is not None:
        if resp["error"]["code"] == -32601:
            raise JsonrpcMethodNotFound(resp["error"], method, params)
        raise JsonrpcException(resp["error"], method, params)
    return resp["result"]


# Abstract hex-binary conversions
def hex2b(data: Optional[str]) -> bytes:
    """Convert a hexadecimal string into binary data"""
    if data is None:
        return b""
    return bytes.fromhex(data)


def b2hex(data: Union[bytes, bytearray, memoryview, None]) -> str:
    """Convert raw binary data into a hexadecimal string"""
    if data is None:
        return ""
    if not isinstance(data, bytes):
        data = bytes(data)
    return bytes.hex(data)
