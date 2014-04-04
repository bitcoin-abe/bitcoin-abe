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

import re
import base58
import Crypto.Hash.SHA256 as SHA256

try:
    import Crypto.Hash.RIPEMD160 as RIPEMD160
except Exception:
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

NULL_HASH = "\0" * 32
GENESIS_HASH_PREV = NULL_HASH

def double_sha256(s):
    return SHA256.new(SHA256.new(s).digest()).digest()

def pubkey_to_hash(pubkey):
    return RIPEMD160.new(SHA256.new(pubkey).digest()).digest()

def calculate_target(nBits):
    return (nBits & 0xffffff) << (8 * (((nBits >> 24) & 0xff) - 3))

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

def str_to_ds(s):
    import BCDataStream
    ds = BCDataStream.BCDataStream()
    ds.write(s)
    return ds

class CmdLine(object):
    def __init__(self, argv, conf=None):
        self.argv = argv
        if conf is None:
            self.conf = {}
        else:
            self.conf = conf.copy()

    def usage(self):
        return "Sorry, no help is available."

    def init(self):
        import DataStore, readconf, logging, sys
        self.conf.update({ "debug": None, "logging": None })
        self.conf.update(DataStore.CONFIG_DEFAULTS)

        args, argv = readconf.parse_argv(self.argv, self.conf, strict=False)
        if argv and argv[0] in ('-h', '--help'):
            print self.usage()
            return None, []

        logging.basicConfig(
            stream=sys.stdout, level=logging.DEBUG, format="%(message)s")
        if args.logging is not None:
            import logging.config as logging_config
            logging_config.dictConfig(args.logging)

        store = DataStore.new(args)

        return store, argv
