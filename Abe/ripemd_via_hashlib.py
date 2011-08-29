# RIPEMD hash interface via hashlib for those who don't have
# Crypto.Hash.RIPEMD.

import hashlib

def new(data=''):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h
