#
# Misc util routines
#

import Crypto.Hash.SHA256 as SHA256
try:
    import Crypto.Hash.RIPEMD160 as RIPEMD160
except:
    import ripemd_via_hashlib as RIPEMD160

# This function comes from bitcointools, bct-LICENSE.txt.
def determine_db_dir():
    import os
    import os.path
    import platform
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin/")
    elif platform.system() == "Windows":
        return os.path.join(os.environ['APPDATA'], "Bitcoin")
    return os.path.expanduser("~/.bitcoin")

# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')

# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]

def double_sha256(s):
    return SHA256.new(SHA256.new(s).digest()).digest()

# Based on CBlock::BuildMerkleTree().
def merkle(hashes):
    while True:
        size = len(hashes)
        if size <= 1:
            break
        out = []
        for i in xrange(0, size, 2):
            i2 = min(i + 1, size - 1)
            out.append(double_sha256(hashes[i] + hashes[i2]))
        hashes = out
    return hashes and hashes[0]

def pubkey_to_hash(pubkey):
    return RIPEMD160.new(SHA256.new(pubkey).digest()).digest()

def calculate_target(nBits):
    return (nBits & 0xffffff) << (8 * ((nBits >> 24) - 3))

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
