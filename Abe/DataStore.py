# Copyright(C) 2011 by John Tobey <John.Tobey@gmail.com>

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

import os
import re
import binascii

# bitcointools -- modified deserialize.py to return raw transaction
import BCDataStream
import deserialize
import util
import warnings

SCHEMA_VERSION = "Abe28"

CONFIG_DEFAULTS = {
    "dbtype":       None,
    "connect_args": None,
    "binary_type":  None,
    "upgrade":      None,
    "commit_bytes": None,
    "log_sql":      None,
    "datadir":      None,
}

WORK_BITS = 304  # XXX more than necessary.

CHAIN_CONFIG = [
    {"chain":"Bitcoin",
     "code3":"BTC", "address_version":"\x00", "magic":"\xf9\xbe\xb4\xd9"},
    {"chain":"Testnet",
     "code3":"BC0", "address_version":"\x6f", "magic":"\xfa\xbf\xb5\xda"},
    {"chain":"Namecoin",
     "code3":"NMC", "address_version":"\x34", "magic":"\xf9\xbe\xb4\xfe"},
    {"chain":"Weeds", "network":"Weedsnet",
     "code3":"WDS", "address_version":"\xf3", "magic":"\xf8\xbf\xb5\xda"},
    {"chain":"BeerTokens",
     "code3":"BER", "address_version":"\xf2", "magic":"\xf7\xbf\xb5\xdb"},
    {"chain":"SolidCoin",
     "code3":"SCN", "address_version":"\x7d", "magic":"\xde\xad\xba\xbe"},
    {"chain":"ScTestnet",
     "code3":"SC0", "address_version":"\x6f", "magic":"\xca\xfe\xba\xbe"},
    #{"chain":"",
    # "code3":"", "address_version":"\x", "magic":""},
    ]

NULL_HASH = "\0" * 32
GENESIS_HASH_PREV = NULL_HASH

NULL_PUBKEY_HASH = "\0" * 20
NULL_PUBKEY_ID = 0
PUBKEY_ID_NETWORK_FEE = NULL_PUBKEY_ID

# Regex to match a pubkey hash ("Bitcoin address transaction") in
# txout_scriptPubKey.  Tolerate OP_NOP (0x61) at the end, seen in Bitcoin
# 127630 and 128239.
SCRIPT_ADDRESS_RE = re.compile("\x76\xa9\x14(.{20})\x88\xac\x61?\\Z", re.DOTALL)

# Regex to match a pubkey ("IP address transaction") in txout_scriptPubKey.
SCRIPT_PUBKEY_RE = re.compile("\x41(.{65})\xac\\Z", re.DOTALL)

# Script that can never be redeemed, used in Namecoin.
SCRIPT_NETWORK_FEE = '\x6a'

NO_CLOB = 'BUG_NO_CLOB'

# XXX This belongs in another module.
class InvalidBlock(Exception):
    pass
class MerkleRootMismatch(InvalidBlock):
    def __init__(ex, block_hash, tx_hashes):
        ex.block_hash = block_hash
        ex.tx_hashes = tx_hashes
    def __str__(ex):
        return 'Block header Merkle root does not match its transactions. ' \
            'block hash=%s' % (binascii.hexlify(ex.block_hash),)

class DataStore(object):

    """
    Bitcoin data storage class based on DB-API 2 and SQL1992 with
    workarounds to support SQLite3 and PostgreSQL/psycopg2.
    """

    def __init__(store, args):
        """
        Opens and stores a connection to the SQL database.

        args.dbtype should name a DB-API 2 driver module, e.g.,
        "sqlite3".

        args.connect_args should be an argument to the module's
        connect() method, or None for no argument, or a list of
        arguments, or a dictionary of named arguments.

        args.datadir names Bitcoin data directories containing
        blk0001.dat to scan for new blocks.
        """
        if args.dbtype is None:
            raise TypeError(
                "dbtype is required; please see abe.conf for examples")

        if args.datadir is None:
            args.datadir = util.determine_db_dir()
        if isinstance(args.datadir, str):
            args.datadir = [args.datadir]

        store.args = args
        store.log_sql = args.log_sql
        store.module = __import__(args.dbtype)
        store.conn = store.connect()
        store.cursor = store.conn.cursor()
        store._ddl = store._get_ddl()

        # Read the CONFIG and CONFIGVAR tables if present.
        store.config = store._read_config()

        if store.config is None:
            store.initialize()
        elif store.config['schema_version'] == SCHEMA_VERSION:
            pass
        elif args.upgrade:
            store._set_sql_flavour()
            import upgrade
            upgrade.upgrade_schema(store)
        else:
            raise Exception(
                "Database schema version (%s) does not match software"
                " (%s).  Please run with --upgrade to convert database."
                % (store.config['schema_version'], SCHEMA_VERSION))

        store._set_sql_flavour()
        store._blocks = {}
        store._init_datadirs()

        store.commit_bytes = args.commit_bytes
        if store.commit_bytes is None:
            store.commit_bytes = 100000
        else:
            store.commit_bytes = int(store.commit_bytes)

    def connect(store):
        cargs = store.args.connect_args

        if cargs is None:
            conn = store.module.connect()
        else:
            if isinstance(cargs, dict):
                if ""  in cargs:
                    cargs = cargs.copy()
                    nkwargs = cargs[""]
                    del(cargs[""])
                    if isinstance(nkwargs, list):
                        conn = store.module.connect(*nkwargs, **cargs)
                    else:
                        conn = store.module.connect(nkwargs, **cargs)
                else:
                    conn = store.module.connect(**cargs)
            elif isinstance(cargs, list):
                conn = store.module.connect(*cargs)
            else:
                conn = store.module.connect(cargs)

        return conn

    def reconnect(store):
        print "Reconnecting to database."
        try:
            store.cursor.close()
        except:
            pass
        try:
            store.conn.close()
        except:
            pass
        store.conn = store.connect()
        store.cursor = store.conn.cursor()

    def _read_config(store):
        # Read table CONFIGVAR if it exists.
        config = {}
        try:
            store.cursor.execute("""
                SELECT configvar_name, configvar_value
                  FROM configvar""")
            for name, value in store.cursor.fetchall():
                config[name] = '' if value is None else value
            if config:
                return config

        except store.module.DatabaseError:
            try:
                store.rollback()
            except:
                pass

        # Read legacy table CONFIG if it exists.
        try:
            store.cursor.execute("""
                SELECT schema_version, binary_type
                  FROM config
                 WHERE config_id = 1""")
            row = store.cursor.fetchone()
            sv, btype = row
            return { 'schema_version': sv, 'binary_type': btype }
        except:
            try:
                store.rollback()
            except:
                pass

        # Return None to indicate no schema found.
        return None

    # Accommodate SQL quirks.
    def _set_sql_flavour(store):
        def identity(x):
            return x
        transform = identity
        selectall = store._selectall

        if store.module.paramstyle in ('format', 'pyformat'):
            transform = store._qmark_to_format(transform)
        elif store.module.paramstyle == 'named':
            transform = store._named_to_format(transform)
        elif store.module.paramstyle != 'qmark':
            warnings.warn("Database parameter style is " +
                          "%s, trying qmark" % module.paramstyle)
            pass

        # Binary I/O with the database.
        # Hashes are a special type; since the protocol treats them as
        # 256-bit integers and represents them as little endian, we
        # have to reverse them in hex to satisfy human expectations.
        def rev(x):
            return x[::-1]
        def to_hex(x):
            return None if x is None else binascii.hexlify(x)
        def from_hex(x):
            return None if x is None else binascii.unhexlify(x)
        def to_hex_rev(x):
            return None if x is None else binascii.hexlify(x[::-1])
        def from_hex_rev(x):
            return None if x is None else binascii.unhexlify(x)[::-1]

        val = store.config.get('binary_type')

        if val in (None, 'str'):
            binin       = identity
            binin_hex   = from_hex
            binout      = identity
            binout_hex  = to_hex
            hashin      = rev
            hashin_hex  = from_hex
            hashout     = rev
            hashout_hex = to_hex

        elif val in ("buffer", "bytearray"):
            if val == "buffer":
                def to_btype(x):
                    return None if x is None else buffer(x)
            else:
                def to_btype(x):
                    return None if x is None else bytearray(x)

            binin       = to_btype
            binin_hex   = lambda x: to_btype(from_hex(x))
            binout      = str
            binout_hex  = to_hex
            hashin      = lambda x: to_btype(rev(x))
            hashin_hex  = lambda x: to_btype(from_hex(x))
            hashout     = rev
            hashout_hex = to_hex

        elif val == "hex":
            transform = store._sql_binary_as_hex(transform)
            binin       = to_hex
            binin_hex   = identity
            binout      = from_hex
            binout_hex  = identity
            hashin      = to_hex_rev
            hashin_hex  = identity
            hashout     = from_hex_rev
            hashout_hex = identity

        else:
            raise Exception("Unsupported binary-type %s" % (val,))

        val = store.config.get('int_type')

        if val in (None, 'int'):
            intin = identity

        elif val == 'decimal':
            import decimal
            intin = decimal.Decimal

        elif val == 'str':
            intin = str
            # Work around sqlite3's integer overflow.
            transform = store._approximate_txout(transform)

        else:
            raise Exception("Unsupported int-type %s" % (val,))

        val = store.config.get('sequence_type')
        if val in (None, 'update'):
            new_id = lambda key: store._new_id_update(key)

        else:
            raise Exception("Unsupported sequence-type %s" % (val,))

        # Convert Oracle LOB to str.
        if hasattr(store.module, "LOB") and isinstance(store.module.LOB, type):
            def fix_lob(fn):
                def ret(x):
                    return None if x is None else fn(str(x))
                return ret
            binout = fix_lob(binout)
            binout_hex = fix_lob(binout_hex)

        val = store.config.get('limit_style')
        if val in (None, 'native'):
            pass
        elif val == 'emulated':
            selectall = store.emulate_limit(selectall)

        store.sql_transform = transform
        store.selectall = selectall
        store._sql_cache = {}

        store.binin       = binin
        store.binin_hex   = binin_hex
        store.binout      = binout
        store.binout_hex  = binout_hex
        store.hashin      = hashin
        store.hashin_hex  = hashin_hex
        store.hashout     = hashout
        store.hashout_hex = hashout_hex

        # Might reimplement these someday...
        store.binout_int = lambda x: int(binout_hex(x), 16)
        def binin_int(x, bits):
            if x is None:
                return None
            return binin_hex(("%%0%dx" % (bits / 4)) % x)
        store.binin_int = binin_int

        store.intin       = intin
        store.new_id      = new_id

    def sql(store, stmt, params=()):
        cached = store._sql_cache.get(stmt)
        if cached is None:
            cached = store.sql_transform(stmt)
            store._sql_cache[stmt] = cached
        if store.log_sql:
            print "SQL:", cached, params
        store.cursor.execute(cached, params)

    def ddl(store, stmt):
        if stmt.lstrip().startswith("CREATE TABLE "):
            stmt += store.config['create_table_epilogue']
        stmt = store._sql_fallback_to_lob(store.sql_transform(stmt))
        if store.log_sql:
            print "SQL DDL:", stmt
        store.cursor.execute(stmt)
        if store.config['ddl_implicit_commit'] == 'false':
            store.commit()

    # Convert standard placeholders to Python "format" style.
    def _qmark_to_format(store, fn):
        def ret(stmt):
            # XXX Simplified by assuming no literals contain "?".
            return fn(stmt.replace('%', '%%').replace("?", "%s"))
        return ret

    # Convert standard placeholders to Python "named" style.
    def _named_to_format(store, fn):
        def ret(stmt):
            i = [0]
            def newname(m):
                i[0] += 1
                return ":p%d" % (i[0],)
            # XXX Simplified by assuming no literals contain "?".
            return fn(re.sub("\\?", newname, stmt))
        return ret

    # Convert the standard BIT type to a hex string for databases
    # and drivers that don't support BIT.
    def _sql_binary_as_hex(store, fn):
        patt = re.compile("BIT((?: VARYING)?)\\(([0-9]+)\\)")
        def fixup(match):
            # XXX This assumes no string literals match.
            return (("VARCHAR(" if match.group(1) else "CHAR(") +
                    str(int(match.group(2)) / 4) + ")")
        def ret(stmt):
            # XXX This assumes no string literals match.
            return fn(patt.sub(fixup, stmt).replace("X'", "'"))
        return ret

    # Converts VARCHAR types that are too long to CLOB or similar.
    def _sql_fallback_to_lob(store, stmt):
        try:
            max_varchar = int(store.config['max_varchar'])
            clob_type = store.config['clob_type']
        except:
            return stmt

        patt = re.compile("VARCHAR\\(([0-9]+)\\)")

        def fixup(match):
            # XXX This assumes no string literals match.
            width = int(match.group(1))
            if width > max_varchar and clob_type != NO_CLOB:
                return clob_type
            return "VARCHAR(%d)" % (width,)

        return patt.sub(fixup, stmt)

    def _approximate_txout(store, fn):
        def ret(stmt):
            return fn(re.sub(
                    r'\btxout_value txout_approx_value\b',
                    'CAST(txout_value AS DOUBLE PRECISION) txout_approx_value',
                    stmt))
        return ret

    def emulate_limit(store, selectall):
        limit_re = re.compile(r"(.*)\bLIMIT\s+(\?|\d+)\s*\Z", re.DOTALL)
        def ret(stmt, params=()):
            match = limit_re.match(stmt)
            if match:
                if match.group(2) == '?':
                    n = params[-1]
                    params = params[:-1]
                else:
                    n = int(match.group(2))
                store.sql(match.group(1), params)
                return [ store.cursor.fetchone() for i in xrange(n) ]
            return selectall(stmt, params)
        return ret

    def selectrow(store, stmt, params=()):
        store.sql(stmt, params)
        ret = store.cursor.fetchone()
        if store.log_sql:
            print "SQL FETCH:", ret
        return ret

    def _selectall(store, stmt, params=()):
        store.sql(stmt, params)
        ret = store.cursor.fetchall()
        if store.log_sql:
            print "SQL FETCHALL:", ret
        return ret

    def _init_datadirs(store):
        datadirs = {}
        for row in store.selectall("""
            SELECT datadir_id, dirname, blkfile_number, blkfile_offset, chain_id
              FROM datadir"""):
            id, dir, num, offs, chain_id = row
            datadirs[dir] = {
                "id": id,
                "dirname": dir,
                "blkfile_number": int(num),
                "blkfile_offset": int(offs),
                "chain_id": None if chain_id is None else int(chain_id)}

        # By default, scan every dir we know.  This doesn't happen in
        # practise, because abe.py sets ~/.bitcoin as default datadir.
        if store.args.datadir is None:
            store.datadirs = datadirs.values()
            return

        store.datadirs = []
        for dircfg in store.args.datadir:
            if isinstance(dircfg, dict):
                dirname = dircfg.get('dirname')
                if dirname is None:
                    raise ValueError(
                        'Missing dirname in datadir configuration: '
                        + str(dircfg))
                if dirname in datadirs:
                    store.datadirs.append(datadirs[dirname])
                    continue

                chain_id = dircfg.get('chain_id')
                if chain_id is None:
                    chain_name = dircfg.get('chain')
                    row = store.selectrow(
                        "SELECT chain_id FROM chain WHERE chain_name = ?",
                        (chain_name,))
                    if row is not None:
                        chain_id = row[0]
                    elif chain_name is not None:
                        chain_id = store.new_id('chain')
                        code3 = dircfg.get('code3')
                        if code3 is None:
                            code3 = '000' if chain_id > 999 else "%03d" % (
                                chain_id,)
                        addr_vers = dircfg.get('address_version')
                        if addr_vers is None:
                            addr_vers = "\0"
                        elif isinstance(addr_vers, unicode):
                            addr_vers = addr_vers.encode('latin_1')
                        store.sql("""
                            INSERT INTO chain (
                                chain_id, chain_name, chain_code3,
                                chain_address_version
                            ) VALUES (?, ?, ?, ?)""",
                                  (chain_id, chain_name, code3,
                                   store.binin(addr_vers)))
                        store.commit()
                        print "Assigned chain_id", chain_id, "to", chain_name

            elif dircfg in datadirs:
                store.datadirs.append(datadirs[dircfg])
                continue
            else:
                # Not a dict.  A string naming a directory holding
                # standard chains.
                dirname = dircfg
                chain_id = None

            store.datadirs.append({
                "id": store.new_id("datadir"),
                "dirname": dirname,
                "blkfile_number": 1,
                "blkfile_offset": 0,
                "chain_id": chain_id,
                })

    def _new_id_update(store, key):
        try:
            row = store.selectrow(
                "SELECT nextid FROM abe_sequences WHERE sequence_key = ?",
                (key,))
        except store.module.DatabaseError:
            # XXX Should not rollback in new_id unless configuring.
            store.rollback()
            store.ddl(store._ddl['abe_sequences'])
            row = None
        if row is None:
            (ret,) = store.selectrow("SELECT MAX(" + key + "_id) FROM " + key)
            ret = 1 if ret is None else ret + 1
            store.sql("INSERT INTO abe_sequences (sequence_key, nextid)"
                      " VALUES (?, ?)", (key, ret))
        else:
            ret = int(row[0])
        store.sql("UPDATE abe_sequences SET nextid = nextid + 1"
                  " WHERE sequence_key = ?",
                  (key,))
        return ret

    def commit(store):
        if store.log_sql:
            print "SQL COMMIT"
        store.conn.commit()

    def rollback(store):
        if store.log_sql:
            print "SQL ROLLBACK"
        store.conn.rollback()

    def close(store):
        if store.log_sql:
            print "SQL CLOSE"
        store.conn.close()

    def _get_ddl(store):
        return {
            "chain_summary":
# XXX I could do a lot with MATERIALIZED views.
"""CREATE VIEW chain_summary AS SELECT
    cc.chain_id,
    cc.in_longest,
    b.block_id,
    b.block_hash,
    b.block_version,
    b.block_hashMerkleRoot,
    b.block_nTime,
    b.block_nBits,
    b.block_nNonce,
    cc.block_height,
    b.prev_block_id,
    prev.block_hash prev_block_hash,
    b.block_chain_work,
    b.block_num_tx,
    b.block_value_in,
    b.block_value_out,
    b.block_total_satoshis,
    b.block_total_seconds,
    b.block_satoshi_seconds,
    b.block_total_ss,
    b.block_ss_destroyed
FROM chain_candidate cc
JOIN block b ON (cc.block_id = b.block_id)
LEFT JOIN block prev ON (b.prev_block_id = prev.block_id)""",

            "txout_detail":
"""CREATE VIEW txout_detail AS SELECT
    cc.chain_id,
    cc.in_longest,
    cc.block_id,
    b.block_hash,
    b.block_height,
    block_tx.tx_pos,
    tx.tx_id,
    tx.tx_hash,
    tx.tx_lockTime,
    tx.tx_version,
    tx.tx_size,
    txout.txout_id,
    txout.txout_pos,
    txout.txout_value,
    txout.txout_scriptPubKey,
    pubkey.pubkey_id,
    pubkey.pubkey_hash,
    pubkey.pubkey
  FROM chain_candidate cc
  JOIN block b ON (cc.block_id = b.block_id)
  JOIN block_tx ON (b.block_id = block_tx.block_id)
  JOIN tx    ON (tx.tx_id = block_tx.tx_id)
  JOIN txout ON (tx.tx_id = txout.tx_id)
  LEFT JOIN pubkey ON (txout.pubkey_id = pubkey.pubkey_id)""",

            "txin_detail":
"""CREATE VIEW txin_detail AS SELECT
    cc.chain_id,
    cc.in_longest,
    cc.block_id,
    b.block_hash,
    b.block_height,
    block_tx.tx_pos,
    tx.tx_id,
    tx.tx_hash,
    tx.tx_lockTime,
    tx.tx_version,
    tx.tx_size,
    txin.txin_id,
    txin.txin_pos,
    txin.txout_id prevout_id,
    txin.txin_scriptSig,
    txin.txin_sequence,
    prevout.txout_value txin_value,
    pubkey.pubkey_id,
    pubkey.pubkey_hash,
    pubkey.pubkey
  FROM chain_candidate cc
  JOIN block b ON (cc.block_id = b.block_id)
  JOIN block_tx ON (b.block_id = block_tx.block_id)
  JOIN tx    ON (tx.tx_id = block_tx.tx_id)
  JOIN txin  ON (tx.tx_id = txin.tx_id)
  LEFT JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
  LEFT JOIN pubkey
      ON (prevout.pubkey_id = pubkey.pubkey_id)""",

            "txout_approx":
# View of txout for drivers like sqlite3 that can not handle large
# integer arithmetic.  For them, we transform the definition of
# txout_approx_value to DOUBLE PRECISION (approximate) by a CAST.
"""CREATE VIEW txout_approx AS SELECT
    txout_id,
    tx_id,
    txout_value txout_approx_value
  FROM txout""",

            "configvar":
# ABE accounting.  This table is read without knowledge of the
# database's SQL quirks, so it must use only the most widely supported
# features.
"""CREATE TABLE configvar (
    configvar_name  VARCHAR(100) NOT NULL PRIMARY KEY,
    configvar_value VARCHAR(255)
)""",

            "abe_sequences":
"""CREATE TABLE abe_sequences (
    sequence_key VARCHAR(100) NOT NULL PRIMARY KEY,
    nextid NUMERIC(30)
)""",
            }

    def initialize(store):
        """
        Create the database schema.
        """
        store.configure()

        for stmt in (

store._ddl['configvar'],

"""CREATE TABLE datadir (
    datadir_id  NUMERIC(10) NOT NULL PRIMARY KEY,
    dirname     VARCHAR(2000) NOT NULL,
    blkfile_number NUMERIC(4) NULL,
    blkfile_offset NUMERIC(20) NULL,
    chain_id    NUMERIC(10) NULL
)""",

# MAGIC lists the magic numbers seen in messages and block files, known
# in the original Bitcoin source as `pchMessageStart'.
"""CREATE TABLE magic (
    magic_id    NUMERIC(10) NOT NULL PRIMARY KEY,
    magic       BIT(32)     UNIQUE NOT NULL,
    magic_name  VARCHAR(100) UNIQUE NOT NULL
)""",

# POLICY identifies a block acceptance policy.
"""CREATE TABLE policy (
    policy_id   NUMERIC(10) NOT NULL PRIMARY KEY,
    policy_name VARCHAR(100) UNIQUE NOT NULL
)""",

# A block of the type used by Bitcoin.
"""CREATE TABLE block (
    block_id      NUMERIC(14) NOT NULL PRIMARY KEY,
    block_hash    BIT(256)    UNIQUE NOT NULL,
    block_version NUMERIC(10),
    block_hashMerkleRoot BIT(256),
    block_nTime   NUMERIC(20),
    block_nBits   NUMERIC(10),
    block_nNonce  NUMERIC(10),
    block_height  NUMERIC(14),
    prev_block_id NUMERIC(14) NULL,
    block_chain_work BIT(""" + str(WORK_BITS) + """),
    block_value_in NUMERIC(30),
    block_value_out NUMERIC(30),
    block_total_satoshis NUMERIC(26),
    block_total_seconds NUMERIC(20),
    block_satoshi_seconds NUMERIC(28),
    block_total_ss NUMERIC(28),
    block_num_tx  NUMERIC(10) NOT NULL,
    block_ss_destroyed NUMERIC(28),
    FOREIGN KEY (prev_block_id)
        REFERENCES block (block_id)
)""",

# CHAIN comprises a magic number, a policy, and (indirectly via
# CHAIN_LAST_BLOCK_ID and the referenced block's ancestors) a genesis
# block, possibly null.  A chain may have a currency code.
"""CREATE TABLE chain (
    chain_id    NUMERIC(10) NOT NULL PRIMARY KEY,
    magic_id    NUMERIC(10) NULL,
    policy_id   NUMERIC(10) NULL,
    chain_name  VARCHAR(100) UNIQUE NOT NULL,
    chain_code3 CHAR(3)     NULL,
    chain_address_version BIT VARYING(800) NOT NULL,
    chain_last_block_id NUMERIC(14) NULL,
    FOREIGN KEY (magic_id)  REFERENCES magic (magic_id),
    FOREIGN KEY (policy_id) REFERENCES policy (policy_id),
    FOREIGN KEY (chain_last_block_id)
        REFERENCES block (block_id)
)""",

# CHAIN_CANDIDATE lists blocks that are, or might become, part of the
# given chain.  IN_LONGEST is 1 when the block is in the chain, else 0.
# IN_LONGEST denormalizes information stored canonically in
# CHAIN.CHAIN_LAST_BLOCK_ID and BLOCK.PREV_BLOCK_ID.
"""CREATE TABLE chain_candidate (
    chain_id      NUMERIC(10) NOT NULL,
    block_id      NUMERIC(14) NOT NULL,
    in_longest    NUMERIC(1),
    block_height  NUMERIC(14),
    PRIMARY KEY (chain_id, block_id),
    FOREIGN KEY (block_id) REFERENCES block (block_id)
)""",
"""CREATE INDEX x_cc_block ON chain_candidate (block_id)""",
"""CREATE INDEX x_cc_chain_block_height
    ON chain_candidate (chain_id, block_height)""",
"""CREATE INDEX x_cc_block_height ON chain_candidate (block_height)""",

# An orphan block must remember its hashPrev.
"""CREATE TABLE orphan_block (
    block_id      NUMERIC(14) NOT NULL PRIMARY KEY,
    block_hashPrev BIT(256)   NOT NULL,
    FOREIGN KEY (block_id) REFERENCES block (block_id)
)""",
"""CREATE INDEX x_orphan_block_hashPrev ON orphan_block (block_hashPrev)""",

# Denormalize the relationship inverse to BLOCK.PREV_BLOCK_ID.
"""CREATE TABLE block_next (
    block_id      NUMERIC(14) NOT NULL,
    next_block_id NUMERIC(14) NOT NULL,
    PRIMARY KEY (block_id, next_block_id),
    FOREIGN KEY (block_id) REFERENCES block (block_id),
    FOREIGN KEY (next_block_id) REFERENCES block (block_id)
)""",

# A transaction of the type used by Bitcoin.
"""CREATE TABLE tx (
    tx_id         NUMERIC(26) NOT NULL PRIMARY KEY,
    tx_hash       BIT(256)    UNIQUE NOT NULL,
    tx_version    NUMERIC(10),
    tx_lockTime   NUMERIC(10),
    tx_size       NUMERIC(10)
)""",

# Presence of transactions in blocks is many-to-many.
"""CREATE TABLE block_tx (
    block_id      NUMERIC(14) NOT NULL,
    tx_id         NUMERIC(26) NOT NULL,
    tx_pos        NUMERIC(10) NOT NULL,
    satoshi_seconds_destroyed NUMERIC(28),
    PRIMARY KEY (block_id, tx_id),
    UNIQUE (block_id, tx_pos),
    FOREIGN KEY (block_id)
        REFERENCES block (block_id),
    FOREIGN KEY (tx_id)
        REFERENCES tx (tx_id)
)""",
"""CREATE INDEX x_block_tx_tx ON block_tx (tx_id)""",

# A public key for sending bitcoins.  PUBKEY_HASH is derivable from a
# Bitcoin or Testnet address.
"""CREATE TABLE pubkey (
    pubkey_id     NUMERIC(26) NOT NULL PRIMARY KEY,
    pubkey_hash   BIT(160)    UNIQUE NOT NULL,
    pubkey        BIT(520)    NULL
)""",

# A transaction out-point.
"""CREATE TABLE txout (
    txout_id      NUMERIC(26) NOT NULL PRIMARY KEY,
    tx_id         NUMERIC(26) NOT NULL,
    txout_pos     NUMERIC(10) NOT NULL,
    txout_value   NUMERIC(30) NOT NULL,
    txout_scriptPubKey BIT VARYING(80000),
    pubkey_id     NUMERIC(26),
    UNIQUE (tx_id, txout_pos),
    FOREIGN KEY (pubkey_id)
        REFERENCES pubkey (pubkey_id)
)""",
"""CREATE INDEX x_txout_pubkey ON txout (pubkey_id)""",

# A transaction in-point.
"""CREATE TABLE txin (
    txin_id       NUMERIC(26) NOT NULL PRIMARY KEY,
    tx_id         NUMERIC(26) NOT NULL,
    txin_pos      NUMERIC(10) NOT NULL,
    txout_id      NUMERIC(26),
    txin_scriptSig BIT VARYING(80000),
    txin_sequence NUMERIC(10),
    UNIQUE (tx_id, txin_pos),
    FOREIGN KEY (tx_id)
        REFERENCES tx (tx_id)
)""",
"""CREATE INDEX x_txin_txout ON txin (txout_id)""",

# While TXIN.TXOUT_ID can not be found, we must remember TXOUT_POS,
# a.k.a. PREVOUT_N.
"""CREATE TABLE unlinked_txin (
    txin_id       NUMERIC(26) NOT NULL PRIMARY KEY,
    txout_tx_hash BIT(256)    NOT NULL,
    txout_pos     NUMERIC(10) NOT NULL,
    FOREIGN KEY (txin_id) REFERENCES txin (txin_id)
)""",
"""CREATE INDEX x_unlinked_txin_outpoint
    ON unlinked_txin (txout_tx_hash, txout_pos)""",

"""CREATE TABLE block_txin (
    block_id      NUMERIC(14) NOT NULL,
    txin_id       NUMERIC(26) NOT NULL,
    out_block_id  NUMERIC(14) NOT NULL,
    PRIMARY KEY (block_id, txin_id),
    FOREIGN KEY (block_id) REFERENCES block (block_id),
    FOREIGN KEY (txin_id) REFERENCES txin (txin_id),
    FOREIGN KEY (out_block_id) REFERENCES block (block_id)
)""",

store._ddl['chain_summary'],
store._ddl['txout_detail'],
store._ddl['txin_detail'],
store._ddl['txout_approx'],

"""CREATE TABLE abe_lock (
    lock_id       NUMERIC(10) NOT NULL PRIMARY KEY,
    pid           VARCHAR(255) NULL
)""",
):
            try:
                store.ddl(stmt)
            except:
                print "Failed:", stmt
                raise

        store.sql("INSERT INTO abe_lock (lock_id) VALUES (1)")

        # Insert some well-known chain metadata.
        for conf in CHAIN_CONFIG:
            for thing in "magic", "policy", "chain":
                if thing + "_id" not in conf:
                    conf[thing + "_id"] = store.new_id(thing)
            if "network" not in conf:
                conf["network"] = conf["chain"]
            for thing in "magic", "policy":
                if thing + "_name" not in conf:
                    conf[thing + "_name"] = conf["network"] + " " + thing
            store.sql("""
                INSERT INTO magic (magic_id, magic, magic_name)
                VALUES (?, ?, ?)""",
                      (conf["magic_id"], store.binin(conf["magic"]),
                       conf["magic_name"]))
            store.sql("""
                INSERT INTO policy (policy_id, policy_name)
                VALUES (?, ?)""",
                      (conf["policy_id"], conf["policy_name"]))
            store.sql("""
                INSERT INTO chain (
                    chain_id, magic_id, policy_id, chain_name, chain_code3,
                    chain_address_version
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                      (conf["chain_id"], conf["magic_id"], conf["policy_id"],
                       conf["chain"], conf["code3"],
                       store.binin(conf["address_version"])))

        store.sql("""
            INSERT INTO pubkey (pubkey_id, pubkey_hash) VALUES (?, ?)""",
                  (NULL_PUBKEY_ID, store.binin(NULL_PUBKEY_HASH)))

        store.save_config()
        store.commit()

    def configure(store):
        store.config = {}

        store.configure_ddl_implicit_commit()
        store.configure_create_table_epilogue()
        store.configure_max_varchar()
        store.configure_clob_type()
        store.configure_binary_type()
        store.configure_int_type()
        store.configure_sequence_type()
        store.configure_limit_style()

    def configure_binary_type(store):
        for val in (
            ['str', 'bytearray', 'buffer', 'hex']
            if store.args.binary_type is None else
            [ store.args.binary_type ]):

            store.config['binary_type'] = val
            store._set_sql_flavour()
            if store._test_binary_type():
                print "binary_type=%s" % (val,)
                return
        raise Exception(
            "No known binary data representation works"
            if store.args.binary_type is None else
            "Binary type " + store.args.binary_type + " fails test")

    def configure_int_type(store):
        for val in ['int', 'decimal', 'str']:
            store.config['int_type'] = val
            store._set_sql_flavour()
            if store._test_int_type():
                print "int_type=%s" % (val,)
                return
        raise Exception("No known large integer representation works")

    def configure_sequence_type(store):
        for val in ['update']:
            store.config['sequence_type'] = val
            store._set_sql_flavour()
            if store._test_sequence_type():
                print "sequence_type=%s" % (val,)
                return
        raise Exception("No known sequence type works")

    def _drop_if_exists(store, otype, name):
        try:
            store.sql("DROP " + otype + " " + name)
            store.commit()
        except store.module.DatabaseError:
            store.rollback()

    def _drop_table_if_exists(store, obj):
        store._drop_if_exists("TABLE", obj)
    def _drop_view_if_exists(store, obj):
        store._drop_if_exists("VIEW", obj)
    def _drop_sequence_if_exists(store, obj):
        store._drop_if_exists("SEQUENCE", obj)

    def configure_ddl_implicit_commit(store):
        if 'create_table_epilogue' not in store.config:
            store.config['create_table_epilogue'] = ''
        for val in ['true', 'false']:
            store.config['ddl_implicit_commit'] = val
            store._set_sql_flavour()
            if store._test_ddl():
                print "ddl_implicit_commit=%s" % (val,)
                return
        raise Exception("Can not test for DDL implicit commit.")

    def _test_ddl(store):
        """Test whether DDL performs implicit commit."""
        store._drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                "CREATE TABLE abe_test_1 ("
                " abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY,"
                " foo VARCHAR(10))")
            store.rollback()
            store.selectall("SELECT MAX(abe_test_1_id) FROM abe_test_1")
            return True
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            print "_test_ddl:", store.config['ddl_implicit_commit'] + ":", e
            store.rollback()
            return False
        finally:
            store._drop_table_if_exists("abe_test_1")

    def configure_create_table_epilogue(store):
        for val in ['', ' ENGINE=InnoDB']:
            store.config['create_table_epilogue'] = val
            store._set_sql_flavour()
            if store._test_transaction():
                print "create_table_epilogue='%s'" % (val,)
                return
        raise Exception("Can not create a transactional table.")

    def _test_transaction(store):
        """Test whether CREATE TABLE needs ENGINE=InnoDB for rollback."""
        store._drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                "CREATE TABLE abe_test_1 (a NUMERIC(12))")
            store.sql("INSERT INTO abe_test_1 (a) VALUES (4)")
            store.commit()
            store.sql("INSERT INTO abe_test_1 (a) VALUES (5)")
            store.rollback()
            data = [int(row[0]) for row in store.selectall(
                    "SELECT a FROM abe_test_1")]
            return data == [4]
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            print "_test_transaction:", \
                store.config['create_table_epilogue'] + ":", e
            store.rollback()
            return False
        finally:
            store._drop_table_if_exists("abe_test_1")

    def configure_max_varchar(store):
        """Find the maximum VARCHAR width, up to 0xffffffff"""
        lo = 0
        hi = 1 << 32
        store.config['max_varchar'] = hi
        store._drop_table_if_exists("abe_test_1")
        while True:
            mid = (lo + hi) / 2
            store._drop_table_if_exists("abe_test_1")
            try:
                store.ddl("""CREATE TABLE abe_test_1
                           (a VARCHAR(%d), b VARCHAR(%d))""" % (mid, mid))
                store.sql("INSERT INTO abe_test_1 (a, b) VALUES ('x', 'y')")
                row = store.selectrow("SELECT a, b FROM abe_test_1")
                if [x for x in row] == ['x', 'y']:
                    lo = mid
                else:
                    hi = mid
            except store.module.DatabaseError, e:
                store.rollback()
                hi = mid
            except Exception, e:
                print "configure_max_varchar: %d:" % (mid,), e
                store.rollback()
                hi = mid
            if lo + 1 == hi:
                store.config['max_varchar'] = str(lo)
                print "max_varchar=" + store.config['max_varchar']
                break
        store._drop_table_if_exists("abe_test_1")

    def configure_clob_type(store):
        """Find the name of the CLOB type, if any."""
        long_str = 'x' * 10000
        store._drop_table_if_exists("abe_test_1")
        for val in ['CLOB', 'LONGTEXT', 'TEXT', 'LONG']:
            try:
                store.ddl("CREATE TABLE abe_test_1 (a %s)" % (val,))
                store.sql("INSERT INTO abe_test_1 (a) VALUES (?)",
                          (store.binin(long_str),))
                out = store.selectrow("SELECT a FROM abe_test_1")[0]
                if store.binout(out) == long_str:
                    store.config['clob_type'] = val
                    print "clob_type=" + val
                    return
                else:
                    print "out=" + repr(out)
            except store.module.DatabaseError, e:
                store.rollback()
            except Exception, e:
                print "configure_clob_type: %s:" % (val,), e
                try:
                    store.rollback()
                except:
                    # Fetching a CLOB really messes up Easysoft ODBC Oracle.
                    store.reconnect()
            finally:
                store._drop_table_if_exists("abe_test_1")
        warnings.warn("No native type found for CLOB.")
        store.config['clob_type'] = NO_CLOB

    def _test_binary_type(store):
        store._drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                "CREATE TABLE abe_test_1 (test_id NUMERIC(2) NOT NULL PRIMARY KEY,"
                " test_bit BIT(256), test_varbit BIT VARYING(80000))")
            val = str(''.join(map(chr, range(32))))
            store.sql("INSERT INTO abe_test_1 (test_id, test_bit, test_varbit)"
                      " VALUES (?, ?, ?)",
                      (1, store.hashin(val), store.binin(val)))
            (bit, vbit) = store.selectrow(
                "SELECT test_bit, test_varbit FROM abe_test_1")
            if store.hashout(bit) != val:
                return False
            if store.binout(vbit) != val:
                return False
            return True
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            print "_test_binary_type:", store.config['binary_type'] + ":", e
            store.rollback()
            return False
        finally:
            store._drop_table_if_exists("abe_test_1")

    def _test_int_type(store):
        store._drop_view_if_exists("abe_test_v1")
        store._drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                """CREATE TABLE abe_test_1 (test_id NUMERIC(2) NOT NULL PRIMARY KEY,
                 txout_value NUMERIC(30), i2 NUMERIC(20))""")
            store.ddl(
                """CREATE VIEW abe_test_v1 AS SELECT test_id,
                 txout_value txout_approx_value, txout_value i1, i2
                 FROM abe_test_1""")
            v1 = 2099999999999999
            v2 = 1234567890
            store.sql("INSERT INTO abe_test_1 (test_id, txout_value, i2)"
                      " VALUES (?, ?, ?)",
                      (1, store.intin(v1), v2))
            store.commit()
            prod, o1 = store.selectrow(
                "SELECT txout_approx_value * i2, i1 FROM abe_test_v1")
            prod = int(prod)
            o1 = int(o1)
            if prod < v1 * v2 * 1.0001 and prod > v1 * v2 * 0.9999 and o1 == v1:
                return True
            return False
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            print "_test_int_type:", store.config['int_type'] + ":", e
            store.rollback()
            return False
        finally:
            store._drop_view_if_exists("abe_test_v1")
            store._drop_table_if_exists("abe_test_1")

    def _test_sequence_type(store):
        store._drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                """CREATE TABLE abe_test_1 (
                    abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY,
                    foo VARCHAR(10))""")
            id1 = store.new_id('abe_test_1')
            id2 = store.new_id('abe_test_1')
            if int(id1) != int(id2):
                return True
            return False
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            print "_test_sequence_type:", store.config['sequence_type'] + ":", e
            store.rollback()
            return False
        finally:
            store._drop_table_if_exists("abe_test_1")

    def configure_limit_style(store):
        for val in ['native', 'emulated']:
            store.config['limit_style'] = val
            store._set_sql_flavour()
            if store._test_limit_style():
                print "limit_style=%s" % (val,)
                return
        raise Exception("Can not emulate LIMIT.")

    def _test_limit_style(store):
        store._drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                """CREATE TABLE abe_test_1 (
                    abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY)""")
            for id in (2, 4, 6, 8):
                store.sql("INSERT INTO abe_test_1 (abe_test_1_id) VALUES (?)",
                          (id,))
            rows = store.selectall(
                """SELECT abe_test_1_id FROM abe_test_1 ORDER BY abe_test_1_id
                    LIMIT 3""")
            return [int(row[0]) for row in rows] == [2, 4, 6]
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            print "_test_limit_style:", store.config['limit_style'] + ":", e
            store.rollback()
            return False
        finally:
            store._drop_table_if_exists("abe_test_1")

    def save_config(store):
        store.config['schema_version'] = SCHEMA_VERSION
        for name in store.config.keys():
            store.save_configvar(name)

    def save_configvar(store, name):
        store.sql("INSERT INTO configvar (configvar_name, configvar_value)"
                  " VALUES (?, ?)", (name, store.config[name]))

    def set_configvar(store, name, value):
        store.config[name] = value
        store.save_configvar(name)

    def _get_block(store, block_id):
        return store._blocks.get(int(block_id))

    def _put_block(store, block_id, prev_id, height):
        block = {
            'prev_id': None if prev_id is None else int(prev_id),
            'height':  None if height  is None else int(height),
            'in_longest_chains': set()}
        store._blocks[int(block_id)] = block
        return block

    def _load_block(store, block_id):
        block = store._get_block(block_id)
        if block is None:
            row = store.selectrow("""
                SELECT prev_block_id, block_height
                  FROM block
                 WHERE block_id = ?""", (block_id,))
            if row is None:
                return None
            prev_id, height = row
            block = store._put_block(block_id, prev_id, height)
            for row in store.selectall("""
                SELECT chain_id
                  FROM chain_candidate
                 WHERE block_id = ? AND in_longest = 1""", (block_id,)):
                (chain_id,) = row
                store._add_block_chain(block_id, chain_id)
        return block

    def _update_block(store, block_id, prev_id, height):
        block = store._get_block(block_id)
        if block:
            block['prev_id'] = int(prev_id)
            block['height'] = int(height)

    def _add_block_chain(store, block_id, chain_id):
        block = store._get_block(block_id)
        if block:
            block['in_longest_chains'].add(int(chain_id))

    def _remove_block_chain(store, block_id, chain_id):
        block = store._get_block(block_id)
        if block:
            block['in_longest_chains'].remove(int(chain_id))

    def is_descended_from(store, block_id, ancestor_id):
#        ret = store._is_descended_from(block_id, ancestor_id)
#        print block_id, "is" + ('' if ret else ' NOT'), "descended from", ancestor_id
#        return ret
#    def _is_descended_from(store, block_id, ancestor_id):
        if block_id == ancestor_id:
            return True
        block = store._load_block(block_id)
        if block['prev_id'] == ancestor_id:
            return True
        ancestor = store._load_block(ancestor_id)
        chains = ancestor['in_longest_chains']
        while True:
            #print "is_descended_from", ancestor_id, block
            if chains.intersection(block['in_longest_chains']):
                return ancestor['height'] <= block['height']
            if block['in_longest_chains'] - chains:
                return False
            if block['prev_id'] is None:
                return None
            block = store._load_block(block['prev_id'])
            if block['prev_id'] == ancestor_id:
                return True
            if block['height'] <= ancestor['height']:
                return False

    def find_prev(store, hash):
        row = store.selectrow("""
            SELECT block_id, block_height, block_chain_work,
                   block_total_satoshis, block_total_seconds,
                   block_satoshi_seconds, block_total_ss, block_nTime
              FROM block
             WHERE block_hash=?""", (store.hashin(hash),))
        if row is None:
            return (None, None, None, None, None, None, None, None)
        (id, height, chain_work, satoshis, seconds, satoshi_seconds,
         total_ss, nTime) = row
        return (id, None if height is None else int(height),
                store.binout_int(chain_work),
                None if satoshis is None else int(satoshis),
                None if seconds is None else int(seconds),
                None if satoshi_seconds is None else int(satoshi_seconds),
                None if total_ss is None else int(total_ss),
                int(nTime))

    def import_block(store, b):

        # Get a new block ID.
        block_id = store.new_id("block")
        b['block_id'] = block_id

        # Import new transactions.
        b['value_in'] = 0
        b['value_out'] = 0
        b['value_destroyed'] = 0
        tx_hash_array = []
        for pos in xrange(len(b['transactions'])):
            tx = b['transactions'][pos]
            if 'hash' not in tx:
                tx['hash'] = util.double_sha256(tx['tx'])
            tx_hash_array.append(tx['hash'])
            tx['tx_id'] = (store.tx_find_id_and_value(tx) or
                           store.import_tx(tx, pos == 0))
            b['value_in'] += tx['value_in']
            b['value_out'] += tx['value_out']
            b['value_destroyed'] += tx['value_destroyed']

        # Verify Merkle root.
        if b['hashMerkleRoot'] != util.merkle(tx_hash_array):
            raise MerkleRootMismatch(b['hash'], tx_hash_array)

        # Look for the parent block.
        hashPrev = b['hashPrev']
        is_genesis = hashPrev == GENESIS_HASH_PREV
        (prev_block_id, prev_height, prev_work, prev_satoshis,
         prev_seconds, prev_ss, prev_total_ss, prev_nTime) = (
            (None, -1, 0, 0, 0, 0, 0, b['nTime'])
            if is_genesis else
            store.find_prev(hashPrev))

        b['prev_block_id'] = prev_block_id
        b['height'] = None if prev_height is None else prev_height + 1
        b['chain_work'] = util.calculate_work(prev_work, b['nBits'])

        store._put_block(block_id, prev_block_id, b['height'])

        if prev_seconds is None:
            b['seconds'] = None
        else:
            b['seconds'] = prev_seconds + b['nTime'] - prev_nTime
        if prev_satoshis is None:
            b['satoshis'] = None
        else:
            b['satoshis'] = prev_satoshis + b['value_out'] - b['value_in'] \
                - b['value_destroyed']

        # Insert the block table row.
        store.sql(
            """INSERT INTO block (
                block_id, block_hash, block_version, block_hashMerkleRoot,
                block_nTime, block_nBits, block_nNonce, block_height,
                prev_block_id, block_chain_work, block_value_in,
                block_value_out, block_total_satoshis,
                block_total_seconds, block_num_tx
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )""",
            (block_id, store.hashin(b['hash']), store.intin(b['version']),
             store.hashin(b['hashMerkleRoot']), store.intin(b['nTime']),
             store.intin(b['nBits']), store.intin(b['nNonce']),
             b['height'], prev_block_id,
             store.binin_int(b['chain_work'], WORK_BITS),
             store.intin(b['value_in']), store.intin(b['value_out']),
             store.intin(b['satoshis']), store.intin(b['seconds']),
             len(b['transactions'])))

        # List the block's transactions in block_tx.
        for tx_pos in xrange(len(b['transactions'])):
            tx = b['transactions'][tx_pos]
            store.sql("""
                INSERT INTO block_tx
                    (block_id, tx_id, tx_pos)
                VALUES (?, ?, ?)""",
                      (block_id, tx['tx_id'], tx_pos))
            print "block_tx", block_id, tx['tx_id']

        # Create rows in block_txin.
        for row in store.selectall("""
            SELECT txin.txin_id, obt.block_id
              FROM block_tx bt
              JOIN txin ON (txin.tx_id = bt.tx_id)
              JOIN txout ON (txin.txout_id = txout.txout_id)
              JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
             WHERE bt.block_id = ?""", (block_id,)):
            (txin_id, oblock_id) = row
            if store.is_descended_from(block_id, oblock_id):
                store.sql("""
                    INSERT INTO block_txin (block_id, txin_id, out_block_id)
                    VALUES (?, ?, ?)""",
                          (block_id, txin_id, oblock_id))

        b['ss_destroyed'] = store._get_block_ss_destroyed(
            block_id, b['nTime'],
            map(lambda tx: tx['tx_id'], b['transactions']))

        if prev_satoshis is not None:
            ss_created = prev_satoshis * (b['nTime'] - prev_nTime)
            b['ss'] = prev_ss + ss_created - b['ss_destroyed']
            b['total_ss'] = prev_total_ss + ss_created

            store.sql("""
                UPDATE block
                   SET block_satoshi_seconds = ?,
                       block_total_ss = ?,
                       block_ss_destroyed = ?
                 WHERE block_id = ?""",
                      (store.intin(b['ss']),
                       store.intin(b['total_ss']),
                       store.intin(b['ss_destroyed']),
                       block_id))

        # Store the inverse hashPrev relationship or mark the block as
        # an orphan.
        if prev_block_id:
            store.sql("""
                INSERT INTO block_next (block_id, next_block_id)
                VALUES (?, ?)""", (prev_block_id, block_id))
        elif not is_genesis:
            store.sql("INSERT INTO orphan_block (block_id, block_hashPrev)" +
                      " VALUES (?, ?)", (block_id, store.hashin(b['hashPrev'])))

        for row in store.selectall("""
            SELECT block_id FROM orphan_block WHERE block_hashPrev = ?""",
                                   (store.hashin(b['hash']),)):
            (orphan_id,) = row
            store.sql("UPDATE block SET prev_block_id = ? WHERE block_id = ?",
                      (block_id, orphan_id))
            store.sql("""
                INSERT INTO block_next (block_id, next_block_id)
                VALUES (?, ?)""", (block_id, orphan_id))
            store.sql("DELETE FROM orphan_block WHERE block_id = ?",
                      (orphan_id,))

        b['top'], new_work = store.adopt_orphans(b, 0)

        return block_id

    def _get_block_ss_destroyed(store, block_id, nTime, tx_ids):
        block_ss_destroyed = 0
        for tx_id in tx_ids:
            destroyed = int(store.selectrow("""
                SELECT COALESCE(SUM(txout_approx.txout_approx_value *
                                    (? - b.block_nTime)), 0)
                  FROM block_txin bti
                  JOIN txin ON (bti.txin_id = txin.txin_id)
                  JOIN txout_approx ON (txin.txout_id = txout_approx.txout_id)
                  JOIN block_tx obt ON (txout_approx.tx_id = obt.tx_id)
                  JOIN block b ON (obt.block_id = b.block_id)
                 WHERE bti.block_id = ? AND txin.tx_id = ?""",
                                            (nTime, block_id, tx_id))[0])
            block_ss_destroyed += destroyed
            store.sql("""
                UPDATE block_tx
                   SET satoshi_seconds_destroyed = ?
                 WHERE block_id = ?
                   AND tx_id = ?""",
                      (store.intin(destroyed), block_id, tx_id))
        return block_ss_destroyed

    # Propagate cumulative values to descendant blocks.  Return info
    # about the longest chain rooted at b.
    def adopt_orphans(store, b, orphan_work):
        block_id = b['block_id']
        next_blocks = store.find_next_blocks(block_id)
        if not next_blocks:
            return b, orphan_work

        height = None if b['height'] is None else b['height'] + 1
        best = None
        best_work = orphan_work

        for row in store.selectall("""
            SELECT bn.next_block_id, b.block_nBits,
                   b.block_value_out - b.block_value_in, block_nTime
              FROM block_next bn
              JOIN block b ON (bn.next_block_id = b.block_id)
             WHERE bn.block_id = ?""", (block_id,)):
            next_id, nBits, generated, nTime = row
            nBits = int(nBits)
            generated = None if generated is None else int(generated)
            nTime = int(nTime)
            new_work = util.calculate_work(orphan_work, nBits)

            if b['chain_work'] is None:
                chain_work = None
            else:
                chain_work = b['chain_work'] + new_work - orphan_work

            if b['seconds'] is None:
                seconds = None
            else:
                seconds = b['seconds'] + nTime - b['nTime']

            if b['satoshis'] is None or generated is None:
                satoshis = None
            else:
                satoshis = b['satoshis'] + generated

            if b['ss'] is None or b['satoshis'] is None or b['seconds'] is None:
                destroyed = None
                ss = None
            else:
                tx_ids = map(
                    lambda row: row[0],
                    store.selectall("""
                        SELECT tx_id
                          FROM block_tx
                         WHERE block_id = ?""", (next_id,)))
                destroyed = store._get_block_ss_destroyed(
                    next_id, nTime, tx_ids)
                ss = b['ss'] + b['satoshis'] * (nTime - b['nTime']) - destroyed

            store.sql("""
                UPDATE block
                   SET block_height = ?,
                       block_chain_work = ?,
                       block_total_seconds = ?,
                       block_total_satoshis = ?,
                       block_satoshi_seconds = ?,
                       block_ss_destroyed = ?
                 WHERE block_id = ?""",
                      (height, store.binin_int(chain_work, WORK_BITS),
                       store.intin(seconds), store.intin(satoshis),
                       store.intin(ss), store.intin(destroyed), next_id))

            store._update_block(next_id, block_id, height)

            if height is not None:
                store.sql("""
                    UPDATE chain_candidate SET block_height = ?
                     WHERE block_id = ?""",
                    (height, next_id))

            nb = {
                "block_id": next_id,
                "height": height,
                "chain_work": chain_work,
                "nTime": nTime,
                "seconds": seconds,
                "satoshis": satoshis,
                "ss": ss}
            ret, work = store.adopt_orphans(nb, new_work)

            if work > best_work:
                best = ret
                best_work = work

        return best, best_work

    def tx_find_id_and_value(store, tx):
        row = store.selectrow("""
            SELECT tx.tx_id, SUM(txout.txout_value), SUM(
                       CASE WHEN txout.pubkey_id > 0 THEN txout.txout_value
                            ELSE 0 END)
              FROM tx
              LEFT JOIN txout ON (tx.tx_id = txout.tx_id)
             WHERE tx_hash = ?
             GROUP BY tx.tx_id""",
                              (store.hashin(tx['hash']),))
        if row:
            tx_id, value_out, undestroyed = row
            value_out = 0 if value_out is None else int(value_out)
            undestroyed = 0 if undestroyed is None else int(undestroyed)
            (value_in,) = store.selectrow("""
                SELECT SUM(prevout.txout_value)
                  FROM txin
                  JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
                 WHERE txin.tx_id = ?""", (tx_id,))
            tx['value_in'] = 0 if value_in is None else int(value_in)
            tx['value_out'] = value_out
            tx['value_destroyed'] = value_out - undestroyed
            return tx_id

        return None

    def import_tx(store, tx, is_coinbase):
        tx_id = store.new_id("tx")
        dbhash = store.hashin(tx['hash'])
        store.sql("""
            INSERT INTO tx (tx_id, tx_hash, tx_version, tx_lockTime, tx_size)
            VALUES (?, ?, ?, ?, ?)""",
                  (tx_id, dbhash, store.intin(tx['version']),
                   store.intin(tx['lockTime']), len(tx['tx'])))

        # Import transaction outputs.
        tx['value_out'] = 0
        tx['value_destroyed'] = 0
        for pos in xrange(len(tx['txOut'])):
            txout = tx['txOut'][pos]
            tx['value_out'] += txout['value']
            txout_id = store.new_id("txout")

            pubkey_id = store.script_to_pubkey_id(txout['scriptPubKey'])
            if pubkey_id is not None and pubkey_id <= 0:
                tx['value_destroyed'] += txout['value']

            store.sql("""
                INSERT INTO txout (
                    txout_id, tx_id, txout_pos, txout_value,
                    txout_scriptPubKey, pubkey_id
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                      (txout_id, tx_id, pos, store.intin(txout['value']),
                       store.binin(txout['scriptPubKey']), pubkey_id))
            for row in store.selectall("""
                SELECT txin_id
                  FROM unlinked_txin
                 WHERE txout_tx_hash = ?
                   AND txout_pos = ?""", (dbhash, pos)):
                (txin_id,) = row
                store.sql("UPDATE txin SET txout_id = ? WHERE txin_id = ?",
                          (txout_id, txin_id))
                store.sql("DELETE FROM unlinked_txin WHERE txin_id = ?",
                          (txin_id,))

        # Import transaction inputs.
        tx['value_in'] = 0
        for pos in xrange(len(tx['txIn'])):
            txin = tx['txIn'][pos]
            txin_id = store.new_id("txin")

            if is_coinbase:
                txout_id = None
            else:
                txout_id, value = store.lookup_txout(
                    txin['prevout_hash'], txin['prevout_n'])
                tx['value_in'] += value

            store.sql("""
                INSERT INTO txin (
                    txin_id, tx_id, txin_pos, txout_id,
                    txin_scriptSig, txin_sequence
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                      (txin_id, tx_id, pos, txout_id,
                       store.binin(txin['scriptSig']),
                       store.intin(txin['sequence'])))
            if not is_coinbase and txout_id is None:
                store.sql("""
                    INSERT INTO unlinked_txin (
                        txin_id, txout_tx_hash, txout_pos
                    ) VALUES (?, ?, ?)""",
                          (txin_id, store.hashin(txin['prevout_hash']),
                           store.intin(txin['prevout_n'])))

        # XXX Could populate PUBKEY.PUBKEY with txin scripts...
        # or leave that to an offline process.  Nothing in this program
        # requires them.
        return tx_id

    # Called to indicate that the given block has the correct magic
    # number and policy for the given chain.  Updates CHAIN_CANDIDATE
    # and CHAIN.CHAIN_LAST_BLOCK_ID as appropriate.
    def offer_block_to_chain(store, b, chain_id):
        if b['chain_work'] is None:
            in_longest = 0
        else:
            # Do we produce a chain longer than the current chain?
            # Query whether the new block (or its tallest descendant)
            # beats the current chain_last_block_id.  Also check
            # whether the current best is our top, which indicates
            # this block is in longest; this can happen in database
            # repair scenarios.
            row = store.selectrow("""
                SELECT b.block_id, b.block_height, b.block_chain_work
                  FROM block b, chain c
                 WHERE c.chain_id = ?
                   AND b.block_id = c.chain_last_block_id""", (chain_id,))
            if row:
                loser_id, loser_height, loser_work = row
                if loser_id <> b['top']['block_id'] and \
                        store.binout_int(loser_work) >= b['top']['chain_work']:
                    row = None
            if row:
                # New longest chain.
                in_longest = 1
                to_connect = []
                to_disconnect = []
                winner_id = b['top']['block_id']
                winner_height = b['top']['height']
                #print "start", winner_height, loser_height
                while loser_height > winner_height:
                    to_disconnect.insert(0, loser_id)
                    loser_id = store.get_prev_block_id(loser_id)
                    loser_height -= 1
                while winner_height > loser_height:
                    to_connect.insert(0, winner_id)
                    winner_id = store.get_prev_block_id(winner_id)
                    winner_height -= 1
                #print "tie", loser_height, loser_id, winner_id
                loser_height = None
                while loser_id <> winner_id:
                    to_disconnect.insert(0, loser_id)
                    loser_id = store.get_prev_block_id(loser_id)
                    to_connect.insert(0, winner_id)
                    winner_id = store.get_prev_block_id(winner_id)
                    winner_height -= 1
                for block_id in to_disconnect:
                    store.disconnect_block(block_id, chain_id)
                for block_id in to_connect:
                    store.connect_block(block_id, chain_id)

            elif b['hashPrev'] == GENESIS_HASH_PREV:
                in_longest = 1  # Assume only one genesis block per chain.  XXX
            else:
                in_longest = 0

        store.sql("""
            INSERT INTO chain_candidate (
                chain_id, block_id, in_longest, block_height
            ) VALUES (?, ?, ?, ?)""",
                  (chain_id, b['block_id'], in_longest, b['height']))
        if in_longest == 1:
            store._add_block_chain(b['block_id'], chain_id)

        if in_longest > 0:
            store.sql("""
                UPDATE chain
                   SET chain_last_block_id = ?
                 WHERE chain_id = ?""", (b['top']['block_id'], chain_id))

    def find_next_blocks(store, block_id):
        ret = []
        for row in store.selectall(
            "SELECT next_block_id FROM block_next WHERE block_id = ?",
            (block_id,)):
            ret.append(row[0])
        return ret

    def get_prev_block_id(store, block_id):
        return store.selectrow(
            "SELECT prev_block_id FROM block WHERE block_id = ?",
            (block_id,))[0]

    def disconnect_block(store, block_id, chain_id):
        #print "disconnect", block_id, chain_id
        store.sql("""
            UPDATE chain_candidate
               SET in_longest = 0
             WHERE block_id = ? AND chain_id = ?""",
                  (block_id, chain_id))
        store._remove_block_chain(block_id, chain_id)

    def connect_block(store, block_id, chain_id):
        #print "connect", block_id, chain_id
        store.sql("""
            UPDATE chain_candidate
               SET in_longest = 1
             WHERE block_id = ? AND chain_id = ?""",
                  (block_id, chain_id))
        store._add_block_chain(block_id, chain_id)

    def lookup_txout(store, tx_hash, txout_pos):
        row = store.selectrow("""
            SELECT txout.txout_id, txout.txout_value
              FROM txout, tx
             WHERE txout.tx_id = tx.tx_id
               AND tx.tx_hash = ?
               AND txout.txout_pos = ?""",
                  (store.hashin(tx_hash), txout_pos))
        return (None, 0) if row is None else (row[0], int(row[1]))

    def script_to_pubkey_id(store, script):
        """Extract address from transaction output script."""
        if script == SCRIPT_NETWORK_FEE:
            return PUBKEY_ID_NETWORK_FEE
        match = SCRIPT_ADDRESS_RE.match(script)
        if match:
            return store.pubkey_hash_to_id(match.group(1))
        match = SCRIPT_PUBKEY_RE.match(script)
        if match:
            return store.pubkey_to_id(match.group(1))

        # Not a standard Bitcoin script as of 2011-08-23.  Namecoin operation?
        # Ignore leading pushes, pops, and nops so long as stack does not
        # underflow and ends up empty.
        opcodes = deserialize.opcodes
        drops = (opcodes.OP_NOP, opcodes.OP_DROP, opcodes.OP_2DROP)
        start = 0
        sp = 0
        for opcode, data, i in deserialize.script_GetOp(script):
            if data is not None or \
                    opcode == opcodes.OP_0 or \
                    opcode == opcodes.OP_1NEGATE or \
                    (opcode >= opcodes.OP_1 and opcode <= opcodes.OP_16):
                sp += 1
                continue
            if opcode in drops:
                to_drop = drops.index(opcode)
                if sp < to_drop:
                    break
                sp -= to_drop
                start = i
                continue
            if sp != 0 or start == 0:
                break
            return store.script_to_pubkey_id(script[start:])

        return None

    def pubkey_hash_to_id(store, pubkey_hash):
        return store._pubkey_id(pubkey_hash, None)

    def pubkey_to_id(store, pubkey):
        pubkey_hash = util.pubkey_to_hash(pubkey)
        return store._pubkey_id(pubkey_hash, pubkey)

    def _pubkey_id(store, pubkey_hash, pubkey):
        dbhash = store.binin(pubkey_hash)  # binin, not hashin for 160-bit
        row = store.selectrow("""
            SELECT pubkey_id
              FROM pubkey
             WHERE pubkey_hash = ?""", (dbhash,))
        if row:
            return row[0]
        pubkey_id = store.new_id("pubkey")
        store.sql("""
            INSERT INTO pubkey (pubkey_id, pubkey_hash, pubkey)
            VALUES (?, ?, ?)""",
                  (pubkey_id, dbhash, store.binin(pubkey)))
        return pubkey_id

    def catch_up(store):
        for dircfg in store.datadirs:
            try:
                store.catch_up_dir(dircfg)
            except Exception, e:
                import traceback
                traceback.print_exc()
                print ("Warning: failed to catch up %s: %s"
                       % (dircfg['dirname'], str(e))), dircfg
                store.rollback()

    # Load all blocks starting at the current file and offset.
    def catch_up_dir(store, dircfg):
        def open_blkfile():
            store._refresh_dircfg(dircfg)
            filename = store.blkfile_name(dircfg)
            ds = BCDataStream.BCDataStream()
            ds.map_file(open(filename, "rb"), 0)
            return ds

        try:
            ds = open_blkfile()
        except IOError, e:
            print "Skipping datadir " + dircfg['dirname'] + ": " + str(e)
            return

        while (True):
            store.import_blkdat(dircfg, ds)

            # Try another file.
            dircfg['blkfile_number'] += 1
            try:
                ds = open_blkfile()
            except IOError:
                # No more block files.
                dircfg['blkfile_number'] -= 1
                return

            dircfg['blkfile_offset'] = 0

    # Load all blocks from the given data stream.
    def import_blkdat(store, dircfg, ds):
        filenum = dircfg['blkfile_number']
        ds.read_cursor = dircfg['blkfile_offset']
        bytes_done = 0

        while filenum == dircfg['blkfile_number']:
            if ds.read_cursor + 8 > len(ds.input):
                break

            offset = ds.read_cursor
            magic = ds.read_bytes(4)

            # Assume blocks obey the respective policy if they get here.
            chain_id = dircfg['chain_id']
            if chain_id is None:
                rows = store.selectall("""
                    SELECT chain.chain_id
                      FROM chain
                      JOIN magic ON (chain.magic_id = magic.magic_id)
                     WHERE magic.magic = ?""",
                                       (store.binin(magic),))
                if len(rows) == 1:
                    chain_id = rows[0][0]
            if chain_id is None:
                if magic[0] == chr(0):
                    # Skip NUL bytes at block end.
                    ds.read_cursor = offset
                    while ds.read_cursor < len(ds.input):
                        size = min(len(ds.input) - ds.read_cursor, 1000)
                        data = ds.read_bytes(size).lstrip("\0")
                        if (data != ""):
                            ds.read_cursor -= len(data)
                            break
                    print "Skipped %d NUL bytes at block end" % (
                        ds.read_cursor - offset,)
                    continue

                filename = store.blkfile_name(dircfg)
                print "chain not found for magic", repr(magic), \
                    "in block file", filename, "at offset", offset
                print ("If file contents have changed, consider forcing a"
                       " rescan: UPDATE datadir SET blkfile_number=1,"
                       " blkfile_offset=0 WHERE dirname='%s'"
                       % (dircfg['dirname'],))
                ds.read_cursor = offset
                break

            length = ds.read_int32()
            if ds.read_cursor + length > len(ds.input):
                print "incomplete block of length", length
                ds.read_cursor = offset
                break

            hash = util.double_sha256(
                ds.input[ds.read_cursor : ds.read_cursor + 80])
            # XXX should decode target and check hash against it to avoid
            # loading garbage data.

            chain_ids = set()
            block_row = store.selectrow("""
                SELECT block_id, block_height, block_chain_work,
                       block_nTime, block_total_seconds,
                       block_total_satoshis, block_satoshi_seconds
                  FROM block
                 WHERE block_hash = ?
            """, (store.hashin(hash),))

            if block_row:
                # Block header already seen.  Don't import the block,
                # but try to add it to a chain.
                # XXX Could rescan transactions in case we loaded an
                # incomplete block or if operating under --rescan.
                ds.read_cursor += length
            else:
                b = deserialize.parse_Block(ds)
                b["hash"] = hash
                store.import_block(b)

            if chain_id is not None:

                if block_row:
                    b = {
                        "block_id":   block_row[0],
                        "height":     block_row[1],
                        "chain_work": store.binout_int(block_row[2]),
                        "nTime":      block_row[3],
                        "seconds":    block_row[4],
                        "satoshis":   block_row[5],
                        "ss":         block_row[6]}
                    if store.selectrow("""
                        SELECT 1
                          FROM chain_candidate
                         WHERE block_id = ?
                           AND chain_id = ?""",
                                    (b['block_id'], chain_id)):
                        print "block", b['block_id'], \
                            "already in chain", chain_id
                        b = None
                    else:
                        if b['height'] == 0:
                            b['hashPrev'] = GENESIS_HASH_PREV
                        else:
                            b['hashPrev'] = 'dummy'  # Fool adopt_orphans.
                        b['top'], new_work = store.adopt_orphans(b, 0)

                if b:
                    store.offer_block_to_chain(b, chain_id)

            bytes_done += length
            if bytes_done > store.commit_bytes :
                print "commit"
                store.save_blkfile_offset(dircfg, ds.read_cursor)
                store.commit()
                store._refresh_dircfg(dircfg)
                bytes_done = 0

        if bytes_done > 0:
            store.save_blkfile_offset(dircfg, ds.read_cursor)
            store.commit()

    def blkfile_name(store, dircfg):
        return os.path.join(dircfg['dirname'], "blk%04d.dat"
                            % (dircfg['blkfile_number'],))

    def save_blkfile_offset(store, dircfg, offset):
        store.sql("""
            UPDATE datadir
               SET blkfile_number = ?,
                   blkfile_offset = ?
             WHERE datadir_id = ?""",
                  (dircfg['blkfile_number'], store.intin(offset),
                   dircfg['id']))
        if store.cursor.rowcount == 0:
            store.sql("""
                INSERT INTO datadir (datadir_id, dirname, blkfile_number,
                    blkfile_offset, chain_id)
                VALUES (?, ?, ?, ?, ?)""",
                      (dircfg['id'], dircfg['dirname'],
                       dircfg['blkfile_number'],
                       store.intin(offset), dircfg['chain_id']))
        dircfg['blkfile_offset'] = offset

    def _refresh_dircfg(store, dircfg):
        row = store.selectrow("""
            SELECT blkfile_number, blkfile_offset
              FROM datadir
             WHERE dirname = ?""", (dircfg['dirname'],))
        if row:
            number, offset = map(int, row)
            if (number > dircfg['blkfile_number'] or
                (number == dircfg['blkfile_number'] and
                 offset > dircfg['blkfile_offset'])):
                dircfg['blkfile_number'] = number
                dircfg['blkfile_offset'] = offset

def new(args):
    return DataStore(args)
