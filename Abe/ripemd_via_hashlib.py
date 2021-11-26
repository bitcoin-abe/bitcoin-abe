# RIPEMD hash interface via hashlib for those who don't have
# Crypto.Hash.RIPEMD.

import hashlib


def new(data=""):
    _hash = hashlib.new("ripemd160")
    _hash.update(data)
    return _hash
