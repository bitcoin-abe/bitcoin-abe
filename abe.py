#!/usr/bin/env python
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

import sys
import os
import warnings
import optparse
import re
from Crypto.Hash import SHA256
from Crypto.Hash import RIPEMD
import binascii
from cgi import escape

# bitcointools -- modified deserialize.py to return raw transaction
from BCDataStream import *
from deserialize import parse_Block
from util import determine_db_dir
import base58

ABE_APPNAME = "ABE"
ABE_VERSION = '0.1.1'
ABE_URL = 'https://github.com/jtobey/bitcoin-abe'
SCHEMA_VERSION = "6"
EMAIL_ADDRESS = "John.Tobey@gmail.com"

# XXX This should probably be a property of chain, or even a query param.
LOG10COIN = 8
COIN = 10 ** LOG10COIN

BITCOIN_MAGIC = "\xf9\xbe\xb4\xd9"
BITCOIN_MAGIC_ID = 1
BITCOIN_POLICY_ID = 1
BITCOIN_CHAIN_ID = 1
BITCOIN_ADDRESS_VERSION = "\0"

TESTNET_MAGIC = "\xfa\xbf\xb5\xda"
TESTNET_MAGIC_ID = 2
TESTNET_POLICY_ID = 2
TESTNET_CHAIN_ID = 2
TESTNET_ADDRESS_VERSION = "\x6f"

NAMECOIN_MAGIC = "\xf9\xbe\xb4\xfe"
NAMECOIN_MAGIC_ID = 3
NAMECOIN_POLICY_ID = 3
NAMECOIN_CHAIN_ID = 3
NAMECOIN_ADDRESS_VERSION = "\x34"

DEFAULT_CHAIN_ID = NAMECOIN_CHAIN_ID

WORK_BITS = 304  # XXX more than necessary.

GENESIS_HASH_PREV = "\0" * 32

SCRIPT_ADDRESS_RE = re.compile("\x76\xa9\x14(.{20})\x88\xac", re.DOTALL)
SCRIPT_PUBKEY_RE = re.compile("\x41(.{65})\xac", re.DOTALL)

class DataStore(object):

    """
    Bitcoin data storage class based on DB-API 2 and SQL1992 with
    workarounds to support Sqlite3 and PostgreSQL/psycopg2.
    """

    def __init__(store, args):
        """
        Opens and stores a connection to the SQL database.

        args.module should be a DB-API 2 driver module, e.g., sqlite3.

        args.connect_args should be an argument to the module's
        connect() method, or None for no argument, or a list of
        arguments, or a dictionary of named arguments.

        args.binary_type should be one of: None, "hex", or "buffer".
        It specifies the representation of binary data such as block
        hashes in the database.  "hex" uses CHAR and VARCHAR types to
        hold hexadecimal numbers, the most portable and least
        efficient option.  "buffer" wraps binary data using the
        built-in buffer() function, which works for sqlite3.

        args.datadirs names Bitcoin data directories containing
        blk0001.dat to scan for new blocks.

        args.rescan should be true if the contents of the block files
        have been changed other than through normal client operation.
        """
        store.args = args
        store.module = args.module
        cargs = args.connect_args

        if cargs is None:
            conn = store.module.connect()
        else:
            if isinstance(cargs, dict):
                conn = store.module.connect(**cargs)
            elif isinstance(cargs, list):
                conn = store.module.connect(*cargs)
            else:
                conn = store.module.connect(cargs)

        store.conn = conn
        store.cursor = conn.cursor()
        store.sequences = {}

        # Read the CONFIG record if present.
        try:
            store.cursor.execute("""
                SELECT schema_version, binary_type
                  FROM config
                 WHERE config_id = 1""")
            row = store.cursor.fetchone()
            if row is None:
                # Select was successful but no row matched?  Strange.
                (sv, btype) = ('unknown', args.binary_type)
            else:
                (sv, btype) = row
            if sv != SCHEMA_VERSION:
                raise Exception(
                    "Database schema version (%s) does not match software"
                    " (%s).  Please upgrade or rebuild your database."
                    % (sv, SCHEMA_VERSION))
            store.initialized = True
            args.binary_type = btype
        except store.module.DatabaseError:
            try:
                store.rollback()
            except:
                pass
            store.initialized = False

        store._set_sql_flavour()
        store._read_datadirs()

    # Accommodate SQL quirks.
    def _set_sql_flavour(store):
        def sqlfn(store, stmt, params=()):
            #print "want to execute", stmt, params
            store.cursor.execute(stmt, params)

        if store.module.paramstyle in ('format', 'pyformat'):
            sqlfn = store.qmark_to_format(sqlfn)
        elif store.module.paramstyle != 'qmark':
            warnings.warn("Database parameter style is " +
                          "%s, trying qmark" % module.paramstyle)
            pass

        # Binary I/O with the database.
        # Hashes are a special type; since the protocol treats them as
        # 256-bit integers and represents them as little endian, we
        # have to reverse them in hex to satisfy human expectations.
        def identity(x):
            return x
        def to_hex(x):
            return None if x is None else binascii.hexlify(x)
        def from_hex(x):
            return None if x is None else binascii.unhexlify(x)
        def to_hex_rev(x):
            return None if x is None else binascii.hexlify(x[::-1])
        def from_hex_rev(x):
            return None if x is None else binascii.unhexlify(x)[::-1]

        if store.args.binary_type is None:
            binin       = identity
            binin_hex   = from_hex
            binout      = identity
            binout_hex  = to_hex
            hashin      = identity
            hashin_hex  = from_hex_rev
            hashout     = identity
            hashout_hex = to_hex_rev

        elif store.args.binary_type == "buffer":
            def to_buffer(x):
                return None if x is None else buffer(x)
            binin       = to_buffer
            binin_hex   = lambda x: to_buffer(from_hex(x))
            binout      = identity
            binout_hex  = to_hex
            hashin      = to_buffer
            hashin_hex  = lambda x: to_buffer(from_hex_rev(x))
            hashout     = identity
            hashout_hex = to_hex_rev

        elif store.args.binary_type == "hex":
            sqlfn = store.sql_binary_as_hex(sqlfn)
            binin       = to_hex
            binin_hex   = identity
            binout      = from_hex
            binout_hex  = identity
            hashin      = to_hex_rev
            hashin_hex  = identity
            hashout     = from_hex_rev
            hashout_hex = identity

        else:
            raise Exception("Unsupported binary-type %s"
                            % store.args.binary_type)

        store.sqlfn = sqlfn
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
        store.binin_int = lambda x, bits: binin_hex(("%%0%dx" % (bits / 4)) % x)

    def sql(store, stmt, params=()):
        store.sqlfn(store, stmt, params)

    # Convert standard placeholders to Python "format" style.
    def qmark_to_format(store, fn):
        def ret(store, stmt, params=()):
            # Simplify by assuming no literals contain "?".
            fn(store, stmt.replace("?", "%s"), params)
        return ret

    # Convert the standard BIT type to a hex string for databases
    # and drivers that don't support BIT.
    def sql_binary_as_hex(store, fn):
        patt = re.compile("BIT((?: VARYING)?)\\(([0-9]+)\\)")
        def fixup(match):
            # This assumes no string literals match.
            return (("VARCHAR(" if match.group(1) else "CHAR(") +
                    str(int(match.group(2)) / 4) + ")")
        def ret(store, stmt, params=()):
            # This assumes no string literals match.
            fn(store, patt.sub(fixup, stmt).replace("X'", "'"), params)
        return ret

    def selectrow(store, stmt, params=()):
        store.sql(stmt, params)
        return store.cursor.fetchone()

    def selectall(store, stmt, params=()):
        store.sql(stmt, params)
        return store.cursor.fetchall()

    def _read_datadirs(store):
        store.datadirs = {}
        if store.initialized:
            for row in store.selectall("""
                SELECT dirname, blkfile_number, blkfile_offset
                  FROM datadir"""):
                dir, num, offs = row
                store.datadirs[dir] = {"blkfile_number": num,
                                       "blkfile_offset": int(offs)}

    # Implement synthetic key sequences in a simple, thread-unsafe manner.
    # Override this if another process or thread may be inserting rows.
    def new_id(store, tname):
        if tname not in store.sequences:
            (max,) = store.selectrow(
                "SELECT MAX(" + tname + "_id) FROM " + tname);
            store.sequences[tname] = 0 if max is None else max
        store.sequences[tname] += 1
        return store.sequences[tname]

    def commit(store):
        store.conn.commit()

    def rollback(store):
        store.conn.rollback()

    def close(store):
        store.conn.close()

    def initialize_if_needed(store):
        """
        Create the database schema if it does not already exist.
        """
        if store.initialized:
            return
        for stmt in (

# ABE accounting.  CONFIG_ID is used only to prevent multiple rows.
"""CREATE TABLE config (
    config_id   NUMERIC(1)  PRIMARY KEY,
    schema_version VARCHAR(20),
    binary_type VARCHAR(20)
)""",
"""CREATE TABLE datadir (
    dirname     VARCHAR(32767) PRIMARY KEY,
    blkfile_number NUMERIC(4),
    blkfile_offset NUMERIC(20)
)""",

# MAGIC lists the magic numbers seen in messages and block files, known
# in the original Bitcoin source as `pchMessageStart'.
"""CREATE TABLE magic (
    magic_id    NUMERIC(10) PRIMARY KEY,
    magic       BIT(32)     UNIQUE NOT NULL,
    magic_name  VARCHAR(100) UNIQUE NOT NULL
)""",

# POLICY identifies a block acceptance policy.
"""CREATE TABLE policy (
    policy_id   NUMERIC(10) PRIMARY KEY,
    policy_name VARCHAR(100) UNIQUE NOT NULL
)""",

# A block of the type used by Bitcoin.
# XXX Should probably index block_height, better chain_id+block_height.
"""CREATE TABLE block (
    block_id      NUMERIC(14) PRIMARY KEY,
    block_hash    BIT(256)    UNIQUE NOT NULL,
    block_version NUMERIC(10),
    block_hashMerkleRoot BIT(256),
    block_nTime   NUMERIC(20),
    block_nBits   NUMERIC(10),
    block_nNonce  NUMERIC(10),
    block_height  NUMERIC(14),
    prev_block_id NUMERIC(14) NULL,
    block_chain_work BIT(""" + str(WORK_BITS) + """),
    FOREIGN KEY (prev_block_id)
        REFERENCES block (block_id)
)""",

# CHAIN comprises a magic number, a policy, and (indirectly via
# CHAIN_LAST_BLOCK_ID and the referenced block's ancestors) a genesis
# block, possibly null.  A chain may have a currency code.
"""CREATE TABLE chain (
    chain_id    NUMERIC(10) PRIMARY KEY,
    magic_id    NUMERIC(10),
    policy_id   NUMERIC(10),
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
    chain_id      NUMERIC(10),
    block_id      NUMERIC(14),
    in_longest    NUMERIC(1),
    PRIMARY KEY (chain_id, block_id)
)""",

# An orphan block must remember its hashPrev.
"""CREATE TABLE orphan_block (
    block_id      NUMERIC(14) PRIMARY KEY,
    block_hashPrev BIT(256)   NOT NULL,
    FOREIGN KEY (block_id) REFERENCES block (block_id)
)""",
"""CREATE INDEX x_orphan_block_hashPrev ON orphan_block (block_hashPrev)""",

# Denormalize the relationship inverse to BLOCK.PREV_BLOCK_ID.
"""CREATE TABLE block_next (
    block_id      NUMERIC(14),
    next_block_id NUMERIC(14),
    PRIMARY KEY (block_id, next_block_id),
    FOREIGN KEY (block_id) REFERENCES block (block_id),
    FOREIGN KEY (next_block_id) REFERENCES block (block_id)
)""",

# A transaction of the type used by Bitcoin.
"""CREATE TABLE tx (
    tx_id         NUMERIC(26) PRIMARY KEY,
    tx_hash       BIT(256)    UNIQUE NOT NULL,
    tx_version    NUMERIC(10),
    tx_lockTime   NUMERIC(10),
    tx_size       NUMERIC(10)
)""",

# Presence of transactions in blocks is many-to-many.
"""CREATE TABLE block_tx (
    block_id      NUMERIC(14),
    tx_id         NUMERIC(26),
    tx_pos        NUMERIC(10) NOT NULL,
    PRIMARY KEY (block_id, tx_id),
    UNIQUE (block_id, tx_pos),
    FOREIGN KEY (block_id)
        REFERENCES block (block_id),
    FOREIGN KEY (tx_id)
        REFERENCES tx (tx_id)
)""",

# A transaction out-point.
"""CREATE TABLE txout (
    txout_id      NUMERIC(26) PRIMARY KEY,
    tx_id         NUMERIC(26),
    txout_pos     NUMERIC(10),
    txout_value   NUMERIC(30) NOT NULL,
    txout_scriptPubKey BIT VARYING(80000),
    pubkey_id     NUMERIC(26),
    UNIQUE (tx_id, txout_pos)
)""",
"""CREATE INDEX x_txout_pubkey ON txout (pubkey_id)""",

# A transaction in-point.
"""CREATE TABLE txin (
    txin_id       NUMERIC(26) PRIMARY KEY,
    tx_id         NUMERIC(26) NOT NULL,
    txin_pos      NUMERIC(10) NOT NULL,
    txout_id      NUMERIC(26),
    txin_scriptSig BIT VARYING(80000),
    txin_sequence NUMERIC(10),
    UNIQUE (tx_id, txin_pos),
    FOREIGN KEY (tx_id)
        REFERENCES tx (tx_id)
)""",

# While TXIN.TXOUT_ID can not be found, we must remember TXOUT_POS,
# a.k.a. PREVOUT_N.
"""CREATE TABLE unlinked_txin (
    txin_id       NUMERIC(26) PRIMARY KEY,
    txout_tx_hash BIT(256)    NOT NULL,
    txout_pos     NUMERIC(10) NOT NULL,
    FOREIGN KEY (txin_id) REFERENCES txin (txin_id)
)""",
"""CREATE INDEX x_unlinked_txin_outpoint
    ON unlinked_txin (txout_tx_hash, txout_pos)""",

# A public key for sending bitcoins.  PUBKEY_HASH is derivable from a
# Bitcoin or Testnet address.
"""CREATE TABLE pubkey (
    pubkey_id     NUMERIC(26) PRIMARY KEY,
    pubkey_hash   BIT(160)    UNIQUE NOT NULL,
    pubkey        BIT(520)    UNIQUE NULL
)""",

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
    b.block_height,
    b.prev_block_id,
    prev.block_hash prev_block_hash,
    b.block_chain_work,
    COUNT(DISTINCT block_tx.tx_id) num_tx,
    SUM(txout.txout_value) value_out
FROM chain_candidate cc
JOIN block b ON (cc.block_id = b.block_id)
LEFT JOIN block prev ON (b.prev_block_id = prev.block_id)
JOIN block_tx on (block_tx.block_id = b.block_id)
JOIN txout USING (tx_id)
GROUP BY
    cc.chain_id,
    cc.in_longest,
    b.block_id,
    b.block_hash,
    b.block_version,
    b.block_hashMerkleRoot,
    b.block_nTime,
    b.block_nBits,
    b.block_nNonce,
    b.block_height,
    b.prev_block_id,
    prev.block_hash,
    b.block_chain_work""",

"""CREATE VIEW txout_detail AS SELECT
    cc.chain_id,
    cc.in_longest,
    block_id,
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
  JOIN block b using (block_id)
  JOIN block_tx USING (block_id)
  JOIN tx    ON (tx.tx_id = block_tx.tx_id)
  JOIN txout ON (tx.tx_id = txout.tx_id)
  LEFT JOIN pubkey USING (pubkey_id)""",

"""CREATE VIEW txin_detail AS SELECT
    cc.chain_id,
    cc.in_longest,
    block_id,
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
  JOIN block b using (block_id)
  JOIN block_tx USING (block_id)
  JOIN tx    ON (tx.tx_id = block_tx.tx_id)
  JOIN txin  ON (tx.tx_id = txin.tx_id)
  LEFT JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
  LEFT JOIN pubkey
      ON (prevout.pubkey_id = pubkey.pubkey_id)""",
):
            try:
                store.sql(stmt)
            except:
                print "Failed:", stmt
                raise

        ins_magic = """INSERT INTO magic (magic_id, magic, magic_name)
            VALUES (?, ?, ?)"""
        ins_policy = """INSERT INTO policy (policy_id, policy_name)
            VALUES (?, ?)"""
        ins_chain = """
            INSERT INTO chain (
                chain_id, magic_id, policy_id, chain_name, chain_code3,
                chain_address_version
            ) VALUES (?, ?, ?, ?, ?, ?)"""

        # Some public data.
        store.sql(ins_magic, (BITCOIN_MAGIC_ID, store.binin(BITCOIN_MAGIC),
                              "Bitcoin"))
        store.sql(ins_magic, (TESTNET_MAGIC_ID, store.binin(TESTNET_MAGIC),
                              "Testnet"))
        store.sql(ins_magic, (NAMECOIN_MAGIC_ID,
                              store.binin(NAMECOIN_MAGIC), "Namecoin"))
        store.sql(ins_policy, (BITCOIN_POLICY_ID, "Bitcoin policy"))
        store.sql(ins_policy, (TESTNET_POLICY_ID, "Testnet policy"))
        store.sql(ins_policy, (NAMECOIN_POLICY_ID, "Namecoin policy"))
        store.sql(ins_chain,
                  (BITCOIN_CHAIN_ID, BITCOIN_MAGIC_ID, BITCOIN_POLICY_ID,
                   'Bitcoin', 'BTC', store.binin(BITCOIN_ADDRESS_VERSION)))
        store.sql(ins_chain,
                  (TESTNET_CHAIN_ID, TESTNET_MAGIC_ID, TESTNET_POLICY_ID,
                   'Testnet', 'BC0', store.binin(TESTNET_ADDRESS_VERSION)))
        store.sql(ins_chain,
                  (NAMECOIN_CHAIN_ID, NAMECOIN_MAGIC_ID, NAMECOIN_POLICY_ID,
                   'Namecoin', 'NMC', store.binin(NAMECOIN_ADDRESS_VERSION)))

        store.sql("""
            INSERT INTO config (
                config_id, schema_version, binary_type
            ) VALUES (1, ?, ?)""",
                  (SCHEMA_VERSION, store.args.binary_type,))

        store.commit()

    def contains_block(store, hash):
        return store.block_hash_to_id(hash)

    def block_hash_to_id(store, hash):
        row = store.selectrow("SELECT block_id FROM block WHERE block_hash = ?",
                              (store.hashin(hash),))
        return row[0] if row else row

    def find_prev(store, hash):
        row = store.selectrow("""
            SELECT block_id, block_height, block_chain_work
              FROM block
             WHERE block_hash=?""", (store.hashin(hash),))
        if row is None:
            return (None, None, None)
        return (row[0], row[1], store.binout_int(row[2]))

    def import_block(store, b):

        # Get a new block ID.
        block_id = store.new_id("block")
        b['block_id'] = block_id

        # Import new transactions.
        for pos in xrange(len(b['transactions'])):
            tx = b['transactions'][pos]
            if 'hash' not in tx:
                tx['hash'] = doubleSha256(tx['tx'])
            tx['tx_id'] = (store.tx_hash_to_id(tx['hash']) or
                           store.import_tx(tx, pos == 0))

        # Look for the parent block.
        hashPrev = b['hashPrev']
        is_genesis = hashPrev == GENESIS_HASH_PREV
        if is_genesis:
            prev_block_id, prev_height, prev_work = (None, -1, 0)
        else:
            prev_block_id, prev_height, prev_work = store.find_prev(hashPrev)

        b['prev_block_id'] = prev_block_id
        b['height'] = None if prev_height is None else prev_height + 1
        b['chain_work'] = calculate_work(prev_work, b['nBits'])

        # Insert the block table row.
        store.sql("""
            INSERT INTO block (
                block_id, block_hash, block_version, block_hashMerkleRoot,
                block_nTime, block_nBits, block_nNonce, block_height,
                prev_block_id, block_chain_work
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (block_id, store.hashin(b['hash']), b['version'],
                   store.hashin(b['hashMerkleRoot']), b['nTime'],
                   b['nBits'], b['nNonce'], b['height'],
                   prev_block_id, store.binin_int(b['chain_work'],
                                                  WORK_BITS)))

        # List the block's transactions in block_tx.
        for tx_pos in xrange(len(b['transactions'])):
            tx = b['transactions'][tx_pos]
            store.sql("INSERT INTO block_tx (block_id, tx_id, tx_pos)" +
                      " VALUES (?, ?, ?)", (block_id, tx['tx_id'], tx_pos))
            print "block_tx", block_id, tx['tx_id']

        # Store the inverse hashPrev relationship or mark the block as
        # an orphan.
        if prev_block_id:
            store.sql("""
                INSERT INTO block_next (block_id, next_block_id)
                VALUES (?, ?)""", (prev_block_id, block_id))
        elif not is_genesis:
            store.sql("INSERT INTO orphan_block (block_id, block_hashPrev)" +
                      " VALUES (?, ?)", (block_id, store.hashin(b['hashPrev'])))

        return block_id

    def adopt_orphans(store, b):
        orphans = store.find_orphans(b['hash'])
        for orphan_id in orphans:
            print "attaching orphan block", orphan_id
            store.sql("""
                UPDATE block
                   SET prev_block_id = ?
                 WHERE block_id = ?""", (b['block_id'], orphan_id))
            store.sql("DELETE FROM orphan_block WHERE block_id = ?",
                      (orphan_id,))

    def find_orphans(store, hash):
        store.sql("""
            SELECT block_id
              FROM orphan_block
             WHERE block_hashPrev = ?""", (store.hashin(hash),))
        return map(lambda row: row[0], store.cursor.fetchall())

    def tx_hash_to_id(store, hash):
        row = store.selectrow("SELECT tx_id FROM tx WHERE tx_hash=?",
                              (store.hashin(hash),))
        return row[0] if row else row

    def import_tx(store, tx, is_coinbase):
        tx_id = store.new_id("tx")
        dbhash = store.hashin(tx['hash'])
        store.sql("""
            INSERT INTO tx (tx_id, tx_hash, tx_version, tx_lockTime, tx_size)
            VALUES (?, ?, ?, ?, ?)""",
                  (tx_id, dbhash, tx['version'], tx['lockTime'], len(tx['tx'])))

        # Import transaction outputs.
        for pos in xrange(len(tx['txOut'])):
            txout = tx['txOut'][pos]
            txout_id = store.new_id("txout")

            pubkey_id = None
            match = SCRIPT_ADDRESS_RE.match(txout['scriptPubKey'])
            if match:
                pubkey_id = store.pubkey_hash_to_id(match.group(1))
            else:
                match = SCRIPT_PUBKEY_RE.match(txout['scriptPubKey'])
                if match:
                    pubkey_id = store.pubkey_to_id(match.group(1))

            store.sql("""
                INSERT INTO txout (
                    txout_id, tx_id, txout_pos, txout_value,
                    txout_scriptPubKey, pubkey_id
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                      (txout_id, tx_id, pos, txout['value'],
                       store.binin(txout['scriptPubKey']), pubkey_id))
            store.sql("""
                UPDATE txin
                   SET txout_id = ?
                 WHERE EXISTS (
                    SELECT 1
                      FROM unlinked_txin utxin
                     WHERE txin.txin_id = utxin.txin_id
                       AND txout_tx_hash = ?
                       AND txout_pos = ?)""",
                      (txout_id, dbhash, pos))
            if (store.cursor.rowcount or 0) > 0:
                store.sql("""
                    DELETE FROM unlinked_txin
                     WHERE txout_tx_hash = ? AND txout_pos = ?)""",
                      (dbhash, pos))

        # Import transaction inputs.
        for pos in xrange(len(tx['txIn'])):
            txin = tx['txIn'][pos]
            txin_id = store.new_id("txin")
            if is_coinbase:
                txout_id = None
            else:
                txout_id = store.lookup_txout_id(txin['prevout_hash'],
                                                 txin['prevout_n'])
            store.sql("""
                INSERT INTO txin (
                    txin_id, tx_id, txin_pos, txout_id,
                    txin_scriptSig, txin_sequence
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                      (txin_id, tx_id, pos, txout_id,
                       store.binin(txin['scriptSig']), txin['sequence']))
            if not is_coinbase and txout_id is None:
                store.sql("""
                    INSERT INTO unlinked_txin (
                        txin_id, txout_tx_hash, txout_pos
                    ) VALUES (?, ?, ?)""",
                          (txin_id, store.hashin(txin['prevout_hash']),
                           txin['prevout_n']))

        # XXX Could populate PUBKEY.PUBKEY with txin scripts...
        # or leave that to an offline process.
        return tx_id

    # Called to indicate that the given block has the correct magic
    # number and policy for the given chain.  Updates CHAIN_CANDIDATE
    # and CHAIN.CHAIN_LAST_BLOCK_ID as appropriate.
    def offer_block_to_chain(store, b, chain_id):
        if b['chain_work'] is None:
            in_longest = 0
        else:
            (top_block_id, top_height, dbwork) = store.find_top(b['block_id'])
            row = store.selectrow("""
                SELECT b.block_id, b.block_height
                  FROM block b, chain c
                 WHERE b.block_id = c.chain_last_block_id
                   AND c.chain_id = ?
                   AND b.block_chain_work < ?""",
                      (chain_id, dbwork))
            if row:
                in_longest = 1
                (loser_id, loser_height) = row
                to_connect = []
                to_disconnect = []
                block_id = top_block_id
                height = top_height
                #print "start", top_height, loser_height
                while loser_height > height:
                    to_disconnect.insert(0, loser_id)
                    loser_id = store.get_prev_block_id(loser_id)
                    loser_height -= 1
                while height > loser_height:
                    to_connect.insert(0, block_id)
                    block_id = store.get_prev_block_id(block_id)
                    height -= 1
                #print "tie", loser_height, top_height, loser_id, top_block_id
                while loser_id <> block_id:
                    to_disconnect.insert(0, loser_id)
                    loser_id = store.get_prev_block_id(loser_id)
                    to_connect.insert(0, block_id)
                    block_id = store.get_prev_block_id(block_id)
                for block_id in to_disconnect:
                    store.disconnect_block(block_id, chain_id)
                for block_id in to_connect:
                    store.connect_block(block_id, chain_id)

            elif b['hashPrev'] == GENESIS_HASH_PREV:
                in_longest = 1  # XXX
            else:
                in_longest = 0

        store.sql("""
            INSERT INTO chain_candidate (chain_id, block_id, in_longest)
            VALUES (?, ?, ?)""",
                  (chain_id, b['block_id'], in_longest))

        if in_longest:
            store.sql("""
                UPDATE chain
                   SET chain_last_block_id = ?
                 WHERE chain_id = ?""", (top_block_id, chain_id))

    def find_top(store, block_id):
        next_blocks = store.find_next_blocks(block_id)
        if not next_blocks:
            height, dbwork = store.selectrow("""
                SELECT block_height, block_chain_work
                  FROM block
                 WHERE block_id = ?""", (block_id,))
            return (block_id, height, dbwork)
        best = (0, 0, 0)
        for next_id in next_blocks:
            ret = store.find_top(next_id)
            if ret[2] > best[2]:
                best = ret
        return best

    def find_next_blocks(store, block_id):
        store.sql("SELECT next_block_id FROM block_next WHERE block_id = ?",
                  (block_id,))
        return map(lambda row: row[0], store.cursor.fetchall())

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

    def connect_block(store, block_id, chain_id):
        #print "connect", block_id, chain_id
        store.sql("""
            UPDATE chain_candidate
               SET in_longest = 1
             WHERE block_id = ? AND chain_id = ?""",
                  (block_id, chain_id))

    def lookup_txout_id(store, tx_hash, txout_pos):
        row = store.selectrow("""
            SELECT txout.txout_id
              FROM txout, tx
             WHERE txout.tx_id = tx.tx_id
               AND tx.tx_hash = ?
               AND txout.txout_pos = ?""",
                  (store.hashin(tx_hash), txout_pos))
        return None if row is None else row[0]

    def pubkey_hash_to_id(store, pubkey_hash):
        return store._pubkey_id(pubkey_hash, None)

    def pubkey_to_id(store, pubkey):
        pubkey_hash = RIPEMD.new(SHA256.new(pubkey).digest()).digest()
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
        for dirname in store.args.datadirs:
            store.catch_up_dir(dirname)

    # Load all blocks starting at the current file and offset.
    def catch_up_dir(store, dirname):
        dircfg = store.datadirs.get(dirname)
        if dircfg is None:
            dircfg = {"blkfile_number": 1, "blkfile_offset": 0L}
            store.sql("""
                INSERT INTO datadir (
                    dirname, blkfile_number, blkfile_offset
                ) VALUES (?, ?, ?)""", (dirname, 1, 0))
            store.datadirs[dirname] = dircfg

        def open_blkfile():
            filename = os.path.join(dirname, "blk%04d.dat"
                                    % (dircfg['blkfile_number'],))
            ds = BCDataStream()
            ds.map_file(open(filename, "rb"), 0)
            return ds

        # First attempt failures are fatal.
        ds = open_blkfile()
        ds.read_cursor = dircfg['blkfile_offset']

        while (True):
            store.import_blkdat(dirname, ds)

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
    def import_blkdat(store, dirname, ds):
        bytes_done = 0

        while ds.read_cursor + 8 <= len(ds.input):
            offset = ds.read_cursor
            magic = ds.read_bytes(4)  # XXX should scan past invalid data.
            length = ds.read_int32()
            if ds.read_cursor + length >= len(ds.input):
                ds.read_cursor = offset
                break

            hash = doubleSha256(ds.input[ds.read_cursor : ds.read_cursor + 80])
            # XXX should decode target and check hash against it to avoid
            # loading garbage data.

            if store.contains_block(hash):
                # Block header already seen.  Skip the block.
                # XXX Could rescan transactions in case we loaded an
                # incomplete block or if operating under --rescan.
                ds.read_cursor += length
            else:
                b = parse_Block(ds)
                b["hash"] = hash
                store.import_block(b)

                # Assume blocks obey the respective policy if they get here.
                if magic == BITCOIN_MAGIC:
                    store.offer_block_to_chain(b, BITCOIN_CHAIN_ID)
                elif magic == TESTNET_MAGIC:
                    store.offer_block_to_chain(b, TESTNET_CHAIN_ID)
                elif magic == NAMECOIN_MAGIC:
                    store.offer_block_to_chain(b, NAMECOIN_CHAIN_ID)

                bytes_done += length
                if bytes_done > 100000 :
                    store.save_blkfile_offset(dirname, ds.read_cursor)
                    store.commit()
                    bytes_done = 0

        if bytes_done > 0:
            store.save_blkfile_offset(dirname, ds.read_cursor)
            store.commit()

    def save_blkfile_offset(store, dirname, offset):
        store.sql("""
            UPDATE datadir
               SET blkfile_number = ?,
                   blkfile_offset = ?
             WHERE dirname = ?""",
                  (store.datadirs[dirname]['blkfile_number'], offset, dirname))
        if store.cursor.rowcount == 0:
            raise AssertionError('Missing datadir row: ' + dirname)
        store.datadirs[dirname]['blkfile_offset'] = offset

def doubleSha256(s):
    return SHA256.new(SHA256.new(s).digest()).digest()

def calculate_target(nBits):
    return (nBits & 0xffffff) << (8 * ((nBits >> 24) - 3))

def calculate_difficulty(nBits):
    return ((1 << 224) - 1) * 1000 / (calculate_target(nBits) + 1) / 1000.0

def work_to_difficulty(work):
    return work * ((1 << 224) - 1) * 1000 / (1 << 256) / 1000.0

def calculate_work(prev_work, nBits):
    if prev_work is None:
        return None
    # XXX will this round using the same rules as C++ Bitcoin?
    return prev_work + int((1 << 256) / (calculate_target(nBits) + 1))

def make_store(args):
    store = DataStore(args)
    store.initialize_if_needed()
    store.catch_up()
    return store

class NoSuchChainError(Exception):
    """Thrown when a chain lookup fails"""

class Abe:
    def __init__(abe, store, args):
        abe.store = store
        abe.args = args
        abe.htdocs = os.path.join(os.path.split(__file__)[0], 'htdocs')
        abe.footer = ['<p style="font-size: smaller; font-style: italic">',
                      '<a href="', ABE_URL, '">', ABE_APPNAME, '</a> ',
                      ABE_VERSION, ', ',
                      'questions to <a href="mailto:', escape(EMAIL_ADDRESS),
                      '">', escape(EMAIL_ADDRESS), '</a></p>\n']

    def parse_pi(abe, pi):
        """
        Parse PATH_INFO.  Valid paths:

        /chain/CHAIN/... (e.g., /chain/Bitcoin/b/100000 or /chain/Namecoin/)
        /CHAIN/...  (well_formed is None, so invalid CHAIN gives status 404)
        /b/NNNN
        /block/HASH
        /tx/HASH
        /address/ADDRESS

        Return a 5-tuple: chain identifier, command
        (b|block|tx|address|chain), object identifier (e.g., block
        hash), relative URL to application root (e.g., "../"), and a
        flag indicating that the command is explicit.
        """
        chain = None
        well_formed = None
        dotdot = ''
        while True:
            if chain is None:
                match = re.match("/chain/([^/]+)(/.*)", pi, re.DOTALL)
                if match:
                    (chain, pi) = match.groups()
                    dotdot += '../../'
                    well_formed = True
                    continue

            match = re.match("/b/([0-9]+)\\Z", pi)
            if match:
                return chain, 'b', match.group(1), True, dotdot + '../'

            match = re.match("/(block|tx|address)/(\\w+)\\Z", pi)
            if match:
                return (chain, match.group(1), match.group(2), True,
                        dotdot + '../')

            if chain is None:
                match = re.match("/(\\w+)(/.*)", pi, re.DOTALL)
                if match:
                    (chain, pi) = match.groups()
                    dotdot += '../'
                    continue

            if pi == "/":
                return chain, 'chain', chain, well_formed, dotdot

            return None, None, None, False, None

    def __call__(abe, env, start_response):
        import urlparse
        pi = env['PATH_INFO']
        status = '200 OK'
        body = []
        page = {
            "title": [ABE_APPNAME, " ", ABE_VERSION],
            "body": body,
            "env": env,
            "dotdot": '',  # XXX
            "params": {},
            }
        if 'QUERY_STRING' in env:
            page['params'] = urlparse.parse_qs(env['QUERY_STRING'])

        # Always be up-to-date, even if we means having to wait for a response!
        # XXX Could use threads, timers, or a cron job.
        abe.store.catch_up()

        args = abe.parse_pi(pi)
        found = True
        try:
            found = abe.handle(page, *args)
        except NoSuchChainError, e:
            if args[3]:  # well_formed
                body += ['<p class="error">'
                         'Sorry, I don\'t know about that chain!</p>\n']
            else:
                found = False

        if not found:
            try:
                # Serve static content.
                # XXX Should check file modification time and handle
                # HTTP if-modified-since.  Or just hope serious users
                # will map our htdocs as static in their web server.
                # Hmm, we could help them by mapping some path other
                # than / to it.
                # XXX is "+ pi" adequate for non-POSIX systems?
                found = open(abe.htdocs + pi, "rb")
                import mimetypes
                (type, enc) = mimetypes.guess_type(pi)
                if type is not None:
                    # XXX Should do something with enc if not None.
                    start_response(status, [('Content-type', type)])
                    return found
            except IOError:
                pass

        if not found:
            status = '404 Not Found'
            page["body"] = ['<p class="error">Sorry, ', pi,
                            ' does not exist on this server.</p>']

        start_response(status, [('Content-type', 'application/xhtml+xml'),
                                ('Cache-Control', 'max-age=30')])
        def flatten(l):
            return ''.join(map(flatten, l)) if isinstance(l, list) else str(l)
        return map(flatten,
                   ['<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"\n'
                    '  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\n'
                    '<html xmlns="http://www.w3.org/1999/xhtml"'
                    ' xml:lang="en" lang="en">\n'
                    '<head>\n',
                    '<link rel="stylesheet" type="text/css" href="',
                    page['dotdot'], 'abe.css" />\n'
                    '<link rel="shortcut icon" href="',
                    page['dotdot'], 'favicon.ico" />\n'
                    '<title>', page['title'], '</title>\n</head>\n',
                    '<body>\n', page['body'], abe.footer,
                    '</body></html>'])

    def handle(abe, page, chain, objtype, objid, well_formed, dotdot):
        page['dotdot'] = dotdot
        if objtype == 'b':
            abe.show_block_number(chain, objid, page)
        elif objtype == 'block':
            abe.show_block(objid, page)
        elif objtype == 'tx':
            abe.show_tx(objid, page)
        elif objtype == 'address':
            abe.show_address(objid, page)
        elif objtype == 'chain':
            abe.show_chain(chain, page, well_formed)
        else:
            return False
        return True

    def _chain_fields(abe):
        return ["id", "name", "code3", "address_version", "last_block_id"]

    def _row_to_chain(abe, row):
        if row is None:
            raise NoSuchChainError(symbol)
        chain = {}
        fields = abe._chain_fields()
        for i in range(len(fields)):
            chain[fields[i]] = row[i]
        chain['address_version'] = abe.store.binout(chain['address_version'])
        return chain

    def chain_lookup_by_name(abe, symbol):
        if symbol is None:
            return abe.chain_lookup_by_id(DEFAULT_CHAIN_ID)
        return abe._row_to_chain(abe.store.selectrow("""
            SELECT chain_""" + ", chain_".join(abe._chain_fields()) + """
              FROM chain
             WHERE chain_name = ?""", (symbol,)))

    def chain_lookup_by_id(abe, chain_id):
        return abe._row_to_chain(abe.store.selectrow("""
            SELECT chain_""" + ", chain_".join(abe._chain_fields()) + """
              FROM chain
             WHERE chain_id = ?""", (chain_id,)))

    def show_chain(abe, symbol, page, well_formed):
        chain = abe.chain_lookup_by_name(symbol)

        if symbol is None:
            symbol = chain['name']

        if symbol is not None:
            page['title'] = escape(symbol)
            page['body'] += [
                '<h1>', escape(symbol), '</h1>\n']
        body = page['body']

        count = get_int_param(page, 'count') or 20
        hi = get_int_param(page, 'hi')
        orig_hi = hi

        if hi is None:
            (hi,) = abe.store.selectrow("""
                SELECT b.block_height
                  FROM block b
                  JOIN chain c ON (c.chain_last_block_id = b.block_id)
                 WHERE c.chain_id = ?
            """, (chain['id'],))
            bind = (chain['id'], count)
        if hi is None:
            if orig_hi is None and count > 0:
                body += ['<p>The chain is empty.</p>']
            else:
                body += ['<p class="error">'
                         'The requested range contains no blocks.</p>\n']
            return True

        rows = abe.store.selectall("""
            SELECT block_hash, block_height, block_nTime, num_tx, value_out,
                   block_nBits
              FROM chain_summary
             WHERE chain_id = ?
               AND block_height BETWEEN ? AND ?
               AND in_longest = 1
             ORDER BY block_height DESC LIMIT ?
        """, (chain['id'], hi - count + 1, hi, count))

        def to_html(row):
            (hash, height, nTime, num_tx, value_out, nBits) = row
            return ['<tr><td><a href="block/', abe.store.hashout_hex(hash),
                    '">', height, '</a>'
                    '</td><td>', format_time(int(nTime)),
                    '</td><td>', num_tx,
                    '</td><td>', format_satoshis(int(value_out), chain),
                    '</td><td>', calculate_difficulty(int(nBits)),
                    '</td></tr>\n']

        if hi is None:
            hi = int(rows[0][1])
        basename = os.path.basename(page['env']['PATH_INFO'])

        nav = ['<a href="',
               basename, '?count=', str(count), '">&lt;&lt;</a>']
        nav += [' <a href="', basename, '?hi=', str(hi + count),
                 '&amp;count=', str(count), '">&lt;</a>']
        nav += [' ', '&gt;']
        if hi >= count:
            nav[-1] = ['<a href="', basename, '?hi=', str(hi - count),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        nav += [' ', '&gt;&gt;']
        if hi != count - 1:
            nav[-1] = ['<a href="', basename, '?hi=', str(count - 1),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        for c in (20, 50, 100, 500, 2016):
            nav += [' ']
            if c != count:
                nav += ['<a href="', basename, '?count=', str(c)]
                if hi is not None:
                    nav += ['&amp;hi=', str(max(hi, c - 1))]
                nav += ['">']
            nav += [' ', str(c)]
            if c != count:
                nav += ['</a>']

        for row in abe.store.selectall("""
            SELECT DISTINCT c.chain_name
              FROM chain c join chain_candidate cc USING (chain_id)
             WHERE cc.in_longest = 1"""):
            (name,) = row
            if name != chain['name']:
                nav += [' <a href="', page['dotdot'], 'chain/', escape(name),
                        '/">', escape(name), '</a>']

        body += ['<p>', nav, '</p>\n',
                 '<table><tr><th>Block</th><th>Time</th>',
                 '<th>Transactions</th><th>Value Out</th>',
                 '<th>Difficulty</th></tr>\n',
                 map(to_html, rows), '</table>\n<p>', nav, '</p>\n']
        return True

    def _show_block(abe, where, bind, page, dotdotblock, chain):
        address_version = (BITCOIN_ADDRESS_VERSION if chain is None  # XXX
                           else chain['address_version'])
        body = page['body']
        sql = """
            SELECT
                block_id,
                block_hash,
                block_version,
                block_hashMerkleRoot,
                block_nTime,
                block_nBits,
                block_nNonce,
                block_height,
                prev_block_hash,
                block_chain_work
              FROM chain_summary
             WHERE """ + where
        row = abe.store.selectrow(sql, bind)
        if (row is None):
            body += ['<p class="error">Block not found.</p>']
            return
        (block_id, block_hash, block_version, hashMerkleRoot,
         nTime, nBits, nNonce, height,
         prev_block_hash, block_chain_work) = (
            row[0], abe.store.hashout_hex(row[1]), row[2],
            abe.store.hashout_hex(row[3]), row[4], int(row[5]), row[6],
            row[7], abe.store.hashout_hex(row[8]),
            abe.store.binout_int(row[9]))

        next_list = abe.store.selectall("""
            SELECT DISTINCT n.block_hash, cc.in_longest
              FROM block_next bn
              JOIN block n ON (bn.next_block_id = n.block_id)
              JOIN chain_candidate cc ON (n.block_id = cc.block_id)
             WHERE bn.block_id = ?
             ORDER BY cc.in_longest DESC""",
                                  (block_id,))

        page['title'] = 'Block ' + str(height)
        body += ['<p>Hash: ', block_hash, '<br />\n']

        if prev_block_hash is not None:
            body += ['Previous Block: <a href="', dotdotblock,
                     prev_block_hash, '">', prev_block_hash, '</a><br />\n']
        if next_list:
            body += ['Next Block: ']
        for row in next_list:
            hash = abe.store.hashout_hex(row[0])
            body += ['<a href="', dotdotblock, hash, '">', hash, '</a><br />\n']

        body += ['Height: ', str(height), '<br />\n',
                 'Version: ', block_version, '<br />\n',
                 'hashMerkleRoot: ', hashMerkleRoot, '<br />\n',
                 'Time: ', str(nTime), ' (', format_time(nTime), ')<br />\n',
                 'Difficulty: ', format_difficulty(calculate_difficulty(nBits)),
                 ' (Bits: %x)' % (nBits,), '<br />\n',
                 'Cumulative Difficulty: ', format_difficulty(
                work_to_difficulty(block_chain_work)), '<br />\n'
                 'Nonce: ', str(nNonce), '</p>\n',]

        body += ['<h3>Transactions</h3>\n']

        tx_ids = []
        txs = {}
        block_out = 0
        block_in = 0
        abe.store.sql("""
            SELECT tx_id, tx_hash, tx_size, txout_value, pubkey_hash
              FROM txout_detail
             WHERE block_id = ?
             ORDER BY tx_pos, txout_pos
        """, (block_id,))
        for row in abe.store.cursor:
            tx_id, tx_hash_hex, tx_size, txout_value, pubkey_hash = (
                row[0], abe.store.hashout_hex(row[1]), int(row[2]),
                int(row[3]), abe.store.binout(row[4]))
            tx = txs.get(tx_id)
            if tx is None:
                tx_ids.append(tx_id)
                txs[tx_id] = {
                    "hash": tx_hash_hex,
                    "total_out": 0,
                    "total_in": 0,
                    "out": [],
                    "in": [],
                    "size": tx_size,
                    }
                tx = txs[tx_id]
            tx['total_out'] += txout_value
            block_out += txout_value
            tx['out'].append({
                    "value": txout_value,
                    "address": hash_to_address(address_version, pubkey_hash),
                    })
        abe.store.sql("""
            SELECT tx_id, txin_value, pubkey_hash
              FROM txin_detail
             WHERE block_id = ?
             ORDER BY tx_pos, txin_pos
        """, (block_id,))
        for row in abe.store.cursor:
            tx_id, txin_value, pubkey_hash = (
                row[0], 0 if row[1] is None else int(row[1]),
                abe.store.binout(row[2]))
            tx = txs.get(tx_id)
            if tx is None:
                # Strange, inputs but no outputs?
                tx_ids.append(tx_id)
                #row2 = abe.store.selectrow("""
                #    SELECT tx_hash, tx_size FROM tx WHERE tx_id = ?""",
                #                           (tx_id,))
                txs[tx_id] = {
                    "hash": "AssertionFailedTxInputNoOutput",
                    "total_out": 0,
                    "total_in": 0,
                    "out": [],
                    "in": [],
                    "size": -1,
                    }
                tx = txs[tx_id]
            tx['total_in'] += txin_value
            block_in += txin_value
            tx['in'].append({
                    "value": txin_value,
                    "address": hash_to_address(address_version, pubkey_hash),
                    })

        body += ['<table><tr><th>Transaction</th><th>Fee</th>'
                 '<th>Size (kB)</th><th>From (amount)</th><th>To (amount)</th>'
                 '</tr>\n']
        for tx_id in tx_ids:
            tx = txs[tx_id]
            is_coinbase = (tx_id == tx_ids[0])
            if is_coinbase:
                fees = 0
            else:
                fees = tx['total_in'] - tx['total_out']
            body += ['<tr><td><a href="../tx/' + tx['hash'] + '">',
                     tx['hash'][:10], '...</a>'
                     '</td><td>', format_satoshis(fees, chain),
                     '</td><td>', tx['size'] / 1000.0,
                     '</td><td>']
            if is_coinbase:
                gen = block_out - block_in
                fees = tx['total_out'] - gen
                body += ['Generation: ', format_satoshis(gen, chain),
                         ' + ', format_satoshis(fees, chain), ' total fees']
            else:
                for txin in tx['in']:
                    body += ['<a href="', page['dotdot'], 'address/',
                             txin['address'], '">', txin['address'], '</a>: ',
                             format_satoshis(txin['value'], chain), '<br />']
            body += ['</td><td>']
            for txout in tx['out']:
                body += ['<a href="', page['dotdot'], 'address/',
                         txout['address'], '">', txout['address'], '</a>: ',
                         format_satoshis(txout['value'], chain), '<br />']
            body += ['</td></tr>\n']
        body += '</table>\n'

    def show_block_number(abe, symbol, height, page):
        chain = abe.chain_lookup_by_name(symbol)

        page['body'] = [
            '<h1>', chain['name'], ' Block ', height, '</h1>\n']
        abe._show_block('chain_id = ? AND block_height = ? AND in_longest = 1',
                        (chain['id'], height), page, '../block/', chain)

    def show_block(abe, block_hash, page):
        page['body'] = ['<h1>Block</h1>\n']
        dbhash = abe.store.hashin_hex(block_hash)
        # XXX arbitrary choice: minimum chain_id.
        row = abe.store.selectrow(
            """
            SELECT MIN(cc.chain_id), cc.block_id, b.block_height
              FROM chain_candidate cc JOIN block b USING (block_id)
             WHERE b.block_hash = ?
             GROUP BY cc.block_id, b.block_height""",
            (dbhash,))
        if row is not None:
            chain_id, block_id, height = row
            page['body'][-1] = ['<h1>Block ', height, '</h1>\n']
            abe._show_block('block_id = ?', (block_id,), page, '',
                            abe.chain_lookup_by_id(chain_id))
        else:
            abe._show_block('block_hash = ?', (dbhash,), page, '', None)

    def show_tx(abe, tx_hash, page):
        body = page['body'] = [
            '<h1>Transaction</h1>',
            '<p>Watch this space...</p>']

    def show_address(abe, address, page):
        dbhash = abe.store.binin(base58.bc_address_to_hash_160(address))
        page['title'] = 'Address ' + address
        page['body'] = ['<h1>', page['title'], '</h1>']
        body = page['body']

        chains = {}
        balance = {}
        chain_ids = []
        def adj_balance(chain_id, value):
            if chain_id not in balance:
                chain_ids.append(chain_id)
                chains[chain_id] = abe.chain_lookup_by_id(chain_id)
                balance[chain_id] = 0
            balance[chain_id] += value

        print "dbhash=", dbhash # cae888e1fca6236c3ef25cf044650577943dc2d6
        txout = []
        txin = []
        rows = abe.store.selectall("""
            SELECT
                cc.chain_id,
                b.block_height,
                b.block_nTime,
                tx.tx_hash,
                prevout.txout_value
              FROM chain_candidate cc
              JOIN block b USING (block_id)
              JOIN block_tx USING (block_id)
              JOIN tx USING (tx_id)
              JOIN txin USING (tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey USING (pubkey_id)
             WHERE pubkey_hash = ?
               AND cc.in_longest = 1
             ORDER BY cc.chain_id, b.block_height, block_tx.tx_pos""",
                      (dbhash,))
        for row in rows:
            (chain_id, height, nTime, tx_hash, value) = (
                int(row[0]), int(row[1]), int(row[2]),
                abe.store.hashout_hex(row[3]), int(row[4]))
            adj_balance(chain_id, -value)
            txin.append({
                    "chain_id": chain_id,
                    "height": height,
                    "nTime": nTime,
                    "tx_hash": tx_hash,
                    "value": value,
                    })
            print 'txin', repr(txin[-1])
        rows = abe.store.selectall("""
            SELECT
                cc.chain_id,
                b.block_height,
                b.block_nTime,
                tx.tx_hash,
                txout.txout_value
              FROM chain_candidate cc
              JOIN block b USING (block_id)
              JOIN block_tx USING (block_id)
              JOIN tx USING (tx_id)
              JOIN txout USING (tx_id)
              JOIN pubkey USING (pubkey_id)
             WHERE pubkey_hash = ?
               AND cc.in_longest = 1
             ORDER BY cc.chain_id, b.block_height, block_tx.tx_pos""",
                      (dbhash,))
        for row in rows:
            (chain_id, height, nTime, tx_hash, value) = (
                int(row[0]), int(row[1]), int(row[2]),
                abe.store.hashout_hex(row[3]), int(row[4]))
            adj_balance(chain_id, value)
            txout.append({
                    "chain_id": chain_id,
                    "height": height,
                    "nTime": nTime,
                    "tx_hash": tx_hash,
                    "value": value,
                    })
            print 'txout', repr(txin[-1])

        if (not chain_ids):
            body += ['<p>Address not seen on the network.</p>']
            return

        body += ['<p>Balance: ']
        for chain_id in chain_ids:
            chain = chains[chain_id]
            if chain_id != chain_ids[0]:
                body += [', ']
            body += [format_satoshis(balance[chain_id], chain),
                     ' ', chain['code3']]
        body += ['<br /></p>\n']
        body += ['<h3>Transactions</h3>\n'
                 '<p>Watch this space...</p>']

def get_int_param(page, name):
    vals = page['params'].get(name)
    return vals and int(vals[0])

def format_time(nTime):
    import time
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(nTime)))

def format_satoshis(satoshis, chain):
    # XXX Should find COIN and LOG10COIN from chain.
    if satoshis is None:
        return ''
    if satoshis < 0:
        return '-' + format_satoshis(-satoshis, chain)
    integer = satoshis / COIN
    frac = satoshis % COIN
    return (str(integer) +
            ('.' + (('0' * LOG10COIN) + str(frac))[-LOG10COIN:])
            .rstrip('0').rstrip('.'))

def format_difficulty(diff):
    idiff = int(diff)
    ret = '.' + str(int(round((diff - idiff) * 1000)))
    while idiff > 999:
        ret = (' %03d' % (idiff % 1000,)) + ret
        idiff = idiff / 1000
    return str(idiff) + ret

def hash_to_address(version, hash):
    if hash is None:
        return 'UNKNOWN'
    kh = version + hash
    n = int(binascii.hexlify(kh + (SHA256.new(SHA256.new(kh).digest()).digest()[:4])), 16)
    a = ''
    while (n >= 1):
        a = ('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
             [n % 58][:1] + a)
        n /= 58
    return ('1' if version == '\0' else '') + a

def serve(store):
    args = store.args
    abe = Abe(store, args)
    if args.host or args.port:
        # HTTP server.
        if args.host is None:
            args.host = "localhost"
        from wsgiref.simple_server import make_server
        port = int(args.port or 8888)
        httpd = make_server(args.host, port, abe)
        print "Serving HTTP..."
        try:
            httpd.serve_forever()
        except:
            httpd.shutdown()
            raise
    else:
        from flup.server.fcgi import WSGIServer
        WSGIServer(abe).run()

def parse_argv(argv):
    examples = (
        "PostgreSQL example:\n    --dbtype=psycopg2"
        " --connect-args='{\"database\":\"abe\"}' --binary-type hex\n\n"
        "Sqlite examle: --dbtype=sqlite3 --connect-args='\"abe.sqlite\"'\n\n"
        "To run an HTTP listener, supply either or both of HOST and PORT.\n"
        "By default, %(prog)s runs as a FastCGI service.  To disable this,\n"
        "pass --no-serve.")
    import argparse
    parser = argparse.ArgumentParser(
        description="Another Bitcoin block explorer.", epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter)
                                     
    parser.add_argument("--datadir", dest="datadirs", default=[],
                        metavar="DIR", action="append",
                        help="Look for block files (blk*.dat) in DIR."
                        " May be specified more than once.")
    parser.add_argument("--dbtype", "-d", dest="module", default=None,
                        help="DB-API driver module, by default `sqlite3'.")
    parser.add_argument("--connect-args", "-c", dest="connect_args",
                        default=None, metavar="JSON",
                        help="DB-API connect arguments formatted as a JSON"
                        " scalar, array, or object."
                        " If `--dbtype' is not supplied, this defaults to"
                        " `\":memory:\"'.")
    parser.add_argument("--binary-type", dest="binary_type",
                        choices=["buffer", "hex"],
                        help="Transform binary data to support a noncompliant"
                        " database or driver. Most database software is"
                        " noncompliant regarding binary data. `hex' stores"
                        " bytes as hex strings. `buffer' passes them as"
                        " Python buffer objects.")
    parser.add_argument("--rescan", dest="rescan", default=False,
                        action="store_true", help="Reimport blocks.")
    parser.add_argument("--port", dest="port", default=None, type=int,
                        help="TCP port on which to serve HTTP.")
    parser.add_argument("--host", dest="host", default=None,
                        help="Network interface for HTTP server.")
    parser.add_argument("--no-serve", dest="serve", default=True,
                        action="store_false",
                        help="Exit without handling HTTP or FastCGI requests.")
                        
    args = parser.parse_args(argv)

    if not args.datadirs:
        args.datadirs = [determine_db_dir()]

    if args.module is None:
        args.module = "sqlite3"
        if args.connect_args is None:
            args.connect_args = '":memory:"'
        if args.binary_type is None:
            args.binary_type = "buffer"
    args.module = __import__(args.module)
    if args.connect_args is not None:
        import json
        args.connect_args = json.loads(args.connect_args)

    return args

def main(argv):
    args = parse_argv(argv)
    store = make_store(args)
    if (args.serve):
        serve(store)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
