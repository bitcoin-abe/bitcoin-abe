#
# Misc util routines
#

import re
import base58
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
    while len(hashes) > 1:
        size = len(hashes)
        out = []
        for i in xrange(0, size, 2):
            i2 = min(i + 1, size - 1)
            out.append(double_sha256(hashes[i] + hashes[i2]))
        hashes = out
    return hashes and hashes[0]

def block_hash(block):
    import BCDataStream
    ds = BCDataStream.BCDataStream()
    ds.write_int32(block['version'])
    ds.write(block['hashPrev'])
    ds.write(block['hashMerkleRoot'])
    ds.write_uint32(block['nTime'])
    ds.write_uint32(block['nBits'])
    ds.write_uint32(block['nNonce'])
    return double_sha256(ds.input)

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

def get_search_height(n):
    if n < 2:
        return None
    if n & 1:
        return n >> 1 if n & 2 else n - (n >> 2)
    bit = 2
    while (n & bit) == 0:
        bit <<= 1
    return n - bit

ADDRESS_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{26,}\\Z')

def possible_address(string):
    return ADDRESS_RE.match(string)

def hash_to_address(version, hash):
    vh = version + hash
    return base58.b58encode(vh + double_sha256(vh)[:4])

def decode_check_address(address):
    if possible_address(address):
        version, hash = decode_address(address)
        if hash_to_address(version, hash) == address:
            return version, hash
    return None, None

def decode_address(addr):
    bytes = base58.b58decode(addr, None)
    if len(bytes) < 25:
        bytes = ('\0' * (25 - len(bytes))) + bytes
    return bytes[:-24], bytes[-24:-4]

class JsonrpcException(Exception):
    def __init__(ex, error, method, params):
        Exception.__init__(ex)
        ex.code = error['code']
        ex.message = error['message']
        ex.data = error.get('data')
        ex.method = method
        ex.params = params
    def __str__(ex):
        return ex.method + ": " + ex.message + " (code " + str(ex.code) + ")"

class JsonrpcMethodNotFound(JsonrpcException):
    pass

def jsonrpc(url, method, *params):
    import json, urllib
    postdata = json.dumps({"jsonrpc": "2.0",
                           "method": method, "params": params, "id": "x"})
    respdata = urllib.urlopen(url, postdata).read()
    resp = json.loads(respdata)
    if resp.get('error') is not None:
        if resp['error']['code'] == -32601:
            raise JsonrpcMethodNotFound(resp['error'], method, params)
        raise JsonrpcException(resp['error'], method, params)
    return resp['result']

def is_coinbase_tx(tx):
    return len(tx['txIn']) == 1 and tx['txIn'][0]['prevout_hash'] == \
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
