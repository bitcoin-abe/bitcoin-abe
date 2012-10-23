# Copyright(C) 2011,2012 by John Tobey <John.Tobey@gmail.com>

# DataStore.py: back end database access for Abe.

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

# This module combines three functions that might be better split up:
# 1. A feature-detecting, SQL-transforming database abstraction layer
# 2. Abe's schema
# 3. Abstraction over the schema for importing blocks, etc.

import os
import re
import errno

# bitcointools -- modified deserialize.py to return raw transaction
import BCDataStream
import deserialize
import util
import logging
import base58

SCHEMA_VERSION = "Abe31"

CONFIG_DEFAULTS = {
    "dbtype":             None,
    "connect_args":       None,
    "binary_type":        None,
    "int_type":           None,
    "upgrade":            None,
    "commit_bytes":       None,
    "log_sql":            None,
    "datadir":            None,
    "ignore_bit8_chains": None,
    "use_firstbits":      False,
    "keep_scriptsig":     True,
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
            'block hash=%s' % (ex.block_hash.encode('hex'),)

class DataStore(object):

    """
    Bitcoin data storage class based on DB-API 2 and SQL1992 with
    workarounds to support SQLite3, PostgreSQL/psycopg2, MySQL,
    Oracle, ODBC, and IBM DB2.
    """

    def __init__(store, args):
        """
        Open and store a connection to the SQL database.

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
        store.log = logging.getLogger(__name__)
        store.sqllog = logging.getLogger(__name__ + ".sql")
        if not args.log_sql:
            store.sqllog.setLevel(logging.ERROR)
        store.module = __import__(args.dbtype)
        store.conn = store.connect()
        store.cursor = store.conn.cursor()
        store._blocks = {}

        # Read the CONFIG and CONFIGVAR tables if present.
        store.config = store._read_config()

        if store.config is None:
            store.keep_scriptsig = args.keep_scriptsig
        elif 'keep_scriptsig' in store.config:
            store.keep_scriptsig = store.config.get('keep_scriptsig') == "true"
        else:
            store.keep_scriptsig = CONFIG_DEFAULTS['keep_scriptsig']

        store.refresh_ddl()

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
        store._init_datadirs()
        store.no_bit8_chain_ids = store._find_no_bit8_chain_ids(
            args.ignore_bit8_chains)

        store.commit_bytes = args.commit_bytes
        if store.commit_bytes is None:
            store.commit_bytes = 0  # Commit whenever possible.
        else:
            store.commit_bytes = int(store.commit_bytes)

        store.use_firstbits = (store.config['use_firstbits'] == "true")

    def connect(store):
        cargs = store.args.connect_args

        if cargs is None:
            conn = store.module.connect()
        else:
            try:
                conn = store._connect(cargs)
            except UnicodeError:
                # Perhaps this driver needs its strings encoded.
                # Python's default is ASCII.  Let's try UTF-8, which
                # should be the default anyway.
                #import locale
                #enc = locale.getlocale()[1] or locale.getdefaultlocale()[1]
                enc = 'UTF-8'
                def to_utf8(obj):
                    if isinstance(obj, dict):
                        for k in obj.keys():
                            obj[k] = to_utf8(obj[k])
                    if isinstance(obj, list):
                        return map(to_utf8, obj)
                    if isinstance(obj, unicode):
                        return obj.encode(enc)
                    return obj
                conn = store._connect(to_utf8(cargs))
                store.log.info("Connection required conversion to UTF-8")

        return conn

    def _connect(store, cargs):
        if isinstance(cargs, dict):
            if ""  in cargs:
                cargs = cargs.copy()
                nkwargs = cargs[""]
                del(cargs[""])
                if isinstance(nkwargs, list):
                    return store.module.connect(*nkwargs, **cargs)
                return store.module.connect(nkwargs, **cargs)
            else:
                return store.module.connect(**cargs)
        if isinstance(cargs, list):
            return store.module.connect(*cargs)
        return store.module.connect(cargs)

    def reconnect(store):
        store.log.info("Reconnecting to database.")
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
            transform = store._qmark_to_named(transform)
        elif store.module.paramstyle != 'qmark':
            store.log.warning("Database parameter style is "
                              "%s, trying qmark", module.paramstyle)
            pass

        # Binary I/O with the database.
        # Hashes are a special type; since the protocol treats them as
        # 256-bit integers and represents them as little endian, we
        # have to reverse them in hex to satisfy human expectations.
        def rev(x):
            return x[::-1]
        def to_hex(x):
            return None if x is None else str(x).encode('hex')
        def from_hex(x):
            return None if x is None else x.decode('hex')
        def to_hex_rev(x):
            return None if x is None else str(x)[::-1].encode('hex')
        def from_hex_rev(x):
            return None if x is None else x.decode('hex')[::-1]

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

        elif val in ("buffer", "bytearray", "pg-bytea"):
            if val == "bytearray":
                def to_btype(x):
                    return None if x is None else bytearray(x)
            else:
                def to_btype(x):
                    return None if x is None else buffer(x)

            def to_str(x):
                return None if x is None else str(x)

            binin       = to_btype
            binin_hex   = lambda x: to_btype(from_hex(x))
            binout      = to_str
            binout_hex  = to_hex
            hashin      = lambda x: to_btype(rev(x))
            hashin_hex  = lambda x: to_btype(from_hex(x))
            hashout     = rev
            hashout_hex = to_hex

            if val == "pg-bytea":
                transform = store._sql_binary_as_bytea(transform)

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
            def _intin(x):
                return None if x is None else decimal.Decimal(x)
            intin = _intin

        elif val == 'str':
            def _intin(x):
                return None if x is None else str(x)
            intin = _intin
            # Work around sqlite3's integer overflow.
            transform = store._approximate_txout(transform)

        else:
            raise Exception("Unsupported int-type %s" % (val,))

        val = store.config.get('sequence_type')
        if val in (None, 'update'):
            new_id = lambda key: store._new_id_update(key)
            create_sequence = lambda key: store._create_sequence_update(key)
            drop_sequence = lambda key: store._drop_sequence_update(key)

        elif val == 'mysql':
            new_id = lambda key: store._new_id_mysql(key)
            create_sequence = lambda key: store._create_sequence_mysql(key)
            drop_sequence = lambda key: store._drop_sequence_mysql(key)

        else:
            create_sequence = lambda key: store._create_sequence(key)
            drop_sequence = lambda key: store._drop_sequence(key)

            if val == 'oracle':
                new_id = lambda key: store._new_id_oracle(key)
            elif val == 'nvf':
                new_id = lambda key: store._new_id_nvf(key)
            elif val == 'postgres':
                new_id = lambda key: store._new_id_postgres(key)
            elif val == 'db2':
                new_id = lambda key: store._new_id_db2(key)
                create_sequence = lambda key: store._create_sequence_db2(key)
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
        def binout_int(x):
            if x is None:
                return None
            return int(binout_hex(x), 16)
        def binin_int(x, bits):
            if x is None:
                return None
            return binin_hex(("%%0%dx" % (bits / 4)) % x)
        store.binout_int  = binout_int
        store.binin_int   = binin_int

        store.intin       = intin
        store.new_id      = new_id
        store.create_sequence = create_sequence
        store.drop_sequence = drop_sequence

    def sql(store, stmt, params=()):
        cached = store._sql_cache.get(stmt)
        if cached is None:
            cached = store.sql_transform(stmt)
            store._sql_cache[stmt] = cached
        store.sqllog.info("EXEC: %s %s", cached, params)
        try:
            store.cursor.execute(cached, params)
        except Exception, e:
            store.sqllog.info("EXCEPTION: %s", e)
            raise

    def ddl(store, stmt):
        if stmt.lstrip().startswith("CREATE TABLE "):
            stmt += store.config['create_table_epilogue']
        stmt = store._sql_fallback_to_lob(store.sql_transform(stmt))
        store.sqllog.info("DDL: %s", stmt)
        try:
            store.cursor.execute(stmt)
        except Exception, e:
            store.sqllog.info("EXCEPTION: %s", e)
            raise
        if store.config['ddl_implicit_commit'] == 'false':
            store.commit()

    # Convert standard placeholders to Python "format" style.
    def _qmark_to_format(store, fn):
        def ret(stmt):
            # XXX Simplified by assuming no literals contain "?".
            return fn(stmt.replace('%', '%%').replace("?", "%s"))
        return ret

    # Convert standard placeholders to Python "named" style.
    def _qmark_to_named(store, fn):
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

    # Convert the standard BIT type to the PostgreSQL BYTEA type.
    def _sql_binary_as_bytea(store, fn):
        type_patt = re.compile("BIT((?: VARYING)?)\\(([0-9]+)\\)")
        lit_patt = re.compile("X'((?:[0-9a-fA-F][0-9a-fA-F])*)'")
        def fix_type(match):
            # XXX This assumes no string literals match.
            return "BYTEA"
        def fix_lit(match):
            ret = "'"
            for i in match.group(1).decode('hex'):
                ret += r'\\%03o' % ord(i)
            ret += "'::bytea"
            return ret
        def ret(stmt):
            stmt = type_patt.sub(fix_type, stmt)
            stmt = lit_patt.sub(fix_lit, stmt)
            return fn(stmt)
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
        store.sqllog.debug("FETCH: %s", ret)
        return ret

    def _selectall(store, stmt, params=()):
        store.sql(stmt, params)
        ret = store.cursor.fetchall()
        store.sqllog.debug("FETCHALL: %s", ret)
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
                        store.log.warning("Assigned chain_id %d to %s",
                                          chain_id, chain_name)

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

    def _find_no_bit8_chain_ids(store, no_bit8_chains):
        chains = no_bit8_chains
        if chains is None:
            chains = ["Bitcoin", "Testnet"]
        if isinstance(chains, str):
            chains = [chains]
        ids = set()
        for name in chains:
            rows = store.selectall(
                "SELECT chain_id FROM chain WHERE chain_name = ?", (name,))
            if not rows:
                if no_bit8_chains is not None:
                    # Make them fix their config.
                    raise ValueError(
                        "Unknown chain name in ignore-bit8-chains: " + name)
                continue
            for row in rows:
                ids.add(int(row[0]))
        return ids

    def _new_id_update(store, key):
        """
        Allocate a synthetic identifier by updating a table.
        """
        while True:
            row = store.selectrow(
                "SELECT nextid FROM abe_sequences WHERE sequence_key = ?",
                (key,))
            if row is None:
                raise Exception("Sequence %s does not exist" % (key,))

            ret = row[0]
            store.sql("UPDATE abe_sequences SET nextid = nextid + 1"
                      " WHERE sequence_key = ? AND nextid = ?",
                      (key, ret))
            if store.cursor.rowcount == 1:
                return ret
            store.log.info('Contention on abe_sequences %s:%d', key, ret)

    def _get_sequence_initial_value(store, key):
        (ret,) = store.selectrow("SELECT MAX(" + key + "_id) FROM " + key)
        ret = 1 if ret is None else ret + 1
        return ret

    def _create_sequence_update(store, key):
        store.commit()
        ret = store._get_sequence_initial_value(key)
        try:
            store.sql("INSERT INTO abe_sequences (sequence_key, nextid)"
                      " VALUES (?, ?)", (key, ret))
        except store.module.DatabaseError, e:
            store.rollback()
            try:
                store.ddl(store._ddl['abe_sequences'])
            except:
                store.rollback()
                raise e
            store.sql("INSERT INTO abe_sequences (sequence_key, nextid)"
                      " VALUES (?, ?)", (key, ret))

    def _drop_sequence_update(store, key):
        store.commit()
        store.sql("DELETE FROM abe_sequences WHERE sequence_key = ?", (key,))
        store.commit()

    def _new_id_oracle(store, key):
        (ret,) = store.selectrow("SELECT " + key + "_seq.NEXTVAL FROM DUAL")
        return ret

    def _create_sequence(store, key):
        store.ddl("CREATE SEQUENCE %s_seq START WITH %d"
                  % (key, store._get_sequence_initial_value(key)))

    def _drop_sequence(store, key):
        store.ddl("DROP SEQUENCE %s_seq" % (key,))

    def _new_id_nvf(store, key):
        (ret,) = store.selectrow("SELECT NEXT VALUE FOR " + key + "_seq")
        return ret

    def _new_id_postgres(store, key):
        (ret,) = store.selectrow("SELECT NEXTVAL('" + key + "_seq')")
        return ret

    def _create_sequence_db2(store, key):
        store.commit()
        try:
            rows = store.selectall("SELECT 1 FROM abe_dual")
            if len(rows) != 1:
                store.sql("INSERT INTO abe_dual(x) VALUES ('X')")
        except store.module.DatabaseError, e:
            store.rollback()
            store.drop_table_if_exists('abe_dual')
            store.ddl("CREATE TABLE abe_dual (x CHAR(1))")
            store.sql("INSERT INTO abe_dual(x) VALUES ('X')")
            store.log.info("Created silly table abe_dual")
        store._create_sequence(key)

    def _new_id_db2(store, key):
        (ret,) = store.selectrow("SELECT NEXTVAL FOR " + key + "_seq"
                                 " FROM abe_dual")
        return ret

    def _create_sequence_mysql(store, key):
        store.ddl("CREATE TABLE %s_seq (id BIGINT AUTO_INCREMENT PRIMARY KEY)"
                  " AUTO_INCREMENT=%d"
                  % (key, store._get_sequence_initial_value(key)))

    def _drop_sequence_mysql(store, key):
        store.ddl("DROP TABLE %s_seq" % (key,))

    def _new_id_mysql(store, key):
        store.sql("INSERT INTO " + key + "_seq () VALUES ()")
        (ret,) = store.selectrow("SELECT LAST_INSERT_ID()")
        if ret % 1000 == 0:
            store.sql("DELETE FROM " + key + "_seq WHERE id < ?", (ret,))
        return ret

    def commit(store):
        store.sqllog.info("COMMIT")
        store.conn.commit()

    def rollback(store):
        store.sqllog.info("ROLLBACK")
        store.conn.rollback()

    def close(store):
        store.sqllog.info("CLOSE")
        store.conn.close()

    def get_ddl(store, key):
        return store._ddl[key]

    def refresh_ddl(store):
        store._ddl = {
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
    txin.txout_id prevout_id""" + (""",
    txin.txin_scriptSig,
    txin.txin_sequence""" if store.keep_scriptsig else """,
    NULL txin_scriptSig,
    NULL txin_sequence""") + """,
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

# POLICY identifies a block acceptance policy.  Not currently used,
# but required by CHAIN.
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
    block_height  NUMERIC(14) NULL,
    prev_block_id NUMERIC(14) NULL,
    search_block_id NUMERIC(14) NULL,
    block_chain_work BIT(""" + str(WORK_BITS) + """),
    block_value_in NUMERIC(30) NULL,
    block_value_out NUMERIC(30),
    block_total_satoshis NUMERIC(26) NULL,
    block_total_seconds NUMERIC(20) NULL,
    block_satoshi_seconds NUMERIC(28) NULL,
    block_total_ss NUMERIC(28) NULL,
    block_num_tx  NUMERIC(10) NOT NULL,
    block_ss_destroyed NUMERIC(28) NULL,
    FOREIGN KEY (prev_block_id)
        REFERENCES block (block_id),
    FOREIGN KEY (search_block_id)
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
    txout_id      NUMERIC(26)""" + (""",
    txin_scriptSig BIT VARYING(80000),
    txin_sequence NUMERIC(10)""" if store.keep_scriptsig else "") + """,
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
                store.log.error("Failed: %s", stmt)
                raise

        for key in ['magic', 'policy', 'chain', 'datadir',
                    'tx', 'txout', 'pubkey', 'txin', 'block']:
            store.create_sequence(key)

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

        if store.args.use_firstbits:
            store.config['use_firstbits'] = "true"
            store.ddl(
                """CREATE TABLE abe_firstbits (
                    pubkey_id       NUMERIC(26) NOT NULL,
                    block_id        NUMERIC(14) NOT NULL,
                    address_version BIT VARYING(80) NOT NULL,
                    firstbits       VARCHAR(50) NOT NULL,
                    PRIMARY KEY (address_version, pubkey_id, block_id),
                    FOREIGN KEY (pubkey_id) REFERENCES pubkey (pubkey_id),
                    FOREIGN KEY (block_id) REFERENCES block (block_id)
                )""")
            store.ddl(
                """CREATE INDEX x_abe_firstbits
                    ON abe_firstbits (address_version, firstbits)""")
        else:
            store.config['use_firstbits'] = "false"

        store.config['keep_scriptsig'] = \
            "true" if store.args.keep_scriptsig else "false"

        store.save_config()
        store.commit()

    def get_lock(store):
        if store.version_below('Abe26'):
            return None
        conn = store.connect()
        cur = conn.cursor()
        cur.execute("UPDATE abe_lock SET pid = %d WHERE lock_id = 1"
                    % (os.getpid(),))
        if cur.rowcount != 1:
            raise Exception("unexpected rowcount")
        cur.close()

        # Check whether database supports concurrent updates.  Where it
        # doesn't (SQLite) we get exclusive access automatically.
        try:
            import random
            letters = "".join([chr(random.randint(65, 90)) for x in xrange(10)])
            store.sql("""
                INSERT INTO configvar (configvar_name, configvar_value)
                VALUES (?, ?)""",
                      ("upgrade-lock-" + letters, 'x'))
        except:
            store.release_lock(conn)
            conn = None

        store.rollback()

        # XXX Should reread config.

        return conn

    def release_lock(store, conn):
        if conn:
            conn.rollback()
            conn.close()

    def version_below(store, vers):
        sv = store.config['schema_version'].replace('Abe', '')
        vers = vers.replace('Abe', '')
        return float(sv) < float(vers)

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
            ['str', 'bytearray', 'buffer', 'hex', 'pg-bytea']
            if store.args.binary_type is None else
            [ store.args.binary_type ]):

            store.config['binary_type'] = val
            store._set_sql_flavour()
            if store._test_binary_type():
                store.log.info("binary_type=%s", val)
                return
        raise Exception(
            "No known binary data representation works"
            if store.args.binary_type is None else
            "Binary type " + store.args.binary_type + " fails test")

    def configure_int_type(store):
        for val in (
            ['int', 'decimal', 'str']
            if store.args.int_type is None else
            [ store.args.int_type ]):
            store.config['int_type'] = val
            store._set_sql_flavour()
            if store._test_int_type():
                store.log.info("int_type=%s", val)
                return
        raise Exception("No known large integer representation works")

    def configure_sequence_type(store):
        for val in ['oracle', 'postgres', 'nvf', 'db2', 'mysql', 'update']:
            store.config['sequence_type'] = val
            store._set_sql_flavour()
            if store._test_sequence_type():
                store.log.info("sequence_type=%s", val)
                return
        raise Exception("No known sequence type works")

    def _drop_if_exists(store, otype, name):
        try:
            store.sql("DROP " + otype + " " + name)
            store.commit()
        except store.module.DatabaseError:
            store.rollback()

    def drop_table_if_exists(store, obj):
        store._drop_if_exists("TABLE", obj)
    def drop_view_if_exists(store, obj):
        store._drop_if_exists("VIEW", obj)

    def drop_sequence_if_exists(store, key):
        try:
            store.drop_sequence(key)
        except store.module.DatabaseError:
            store.rollback()

    def drop_column_if_exists(store, table, column):
        try:
            store.ddl("ALTER TABLE " + table + " DROP COLUMN " + column)
        except store.module.DatabaseError:
            store.rollback()

    def configure_ddl_implicit_commit(store):
        if 'create_table_epilogue' not in store.config:
            store.config['create_table_epilogue'] = ''
        for val in ['true', 'false']:
            store.config['ddl_implicit_commit'] = val
            store._set_sql_flavour()
            if store._test_ddl():
                store.log.info("ddl_implicit_commit=%s", val)
                return
        raise Exception("Can not test for DDL implicit commit.")

    def _test_ddl(store):
        """Test whether DDL performs implicit commit."""
        store.drop_table_if_exists("abe_test_1")
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
        except Exception:
            store.rollback()
            return False
        finally:
            store.drop_table_if_exists("abe_test_1")

    def configure_create_table_epilogue(store):
        for val in ['', ' ENGINE=InnoDB']:
            store.config['create_table_epilogue'] = val
            store._set_sql_flavour()
            if store._test_transaction():
                store.log.info("create_table_epilogue='%s'", val)
                return
        raise Exception("Can not create a transactional table.")

    def _test_transaction(store):
        """Test whether CREATE TABLE needs ENGINE=InnoDB for rollback."""
        store.drop_table_if_exists("abe_test_1")
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
            store.rollback()
            return False
        finally:
            store.drop_table_if_exists("abe_test_1")

    def configure_max_varchar(store):
        """Find the maximum VARCHAR width, up to 0xffffffff"""
        lo = 0
        hi = 1 << 32
        mid = hi - 1
        store.config['max_varchar'] = str(mid)
        store.drop_table_if_exists("abe_test_1")
        while True:
            store.drop_table_if_exists("abe_test_1")
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
                store.rollback()
                hi = mid
            if lo + 1 == hi:
                store.config['max_varchar'] = str(lo)
                store.log.info("max_varchar=%s", store.config['max_varchar'])
                break
            mid = (lo + hi) / 2
        store.drop_table_if_exists("abe_test_1")

    def configure_clob_type(store):
        """Find the name of the CLOB type, if any."""
        long_str = 'x' * 10000
        store.drop_table_if_exists("abe_test_1")
        for val in ['CLOB', 'LONGTEXT', 'TEXT', 'LONG']:
            try:
                store.ddl("CREATE TABLE abe_test_1 (a %s)" % (val,))
                store.sql("INSERT INTO abe_test_1 (a) VALUES (?)",
                          (store.binin(long_str),))
                out = store.selectrow("SELECT a FROM abe_test_1")[0]
                if store.binout(out) == long_str:
                    store.config['clob_type'] = val
                    store.log.info("clob_type=%s", val)
                    return
                else:
                    store.log.debug("out=%s", repr(out))
            except store.module.DatabaseError, e:
                store.rollback()
            except Exception, e:
                try:
                    store.rollback()
                except:
                    # Fetching a CLOB really messes up Easysoft ODBC Oracle.
                    store.reconnect()
            finally:
                store.drop_table_if_exists("abe_test_1")
        store.log.info("No native type found for CLOB.")
        store.config['clob_type'] = NO_CLOB

    def _test_binary_type(store):
        store.drop_table_if_exists("abe_test_1")
        try:
            store.ddl(
                "CREATE TABLE abe_test_1 (test_id NUMERIC(2) NOT NULL PRIMARY KEY,"
                " test_bit BIT(256), test_varbit BIT VARYING(80000))")
            val = str(''.join(map(chr, range(0, 256, 8))))
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
            store.rollback()
            return False
        finally:
            store.drop_table_if_exists("abe_test_1")

    def _test_int_type(store):
        store.drop_view_if_exists("abe_test_v1")
        store.drop_table_if_exists("abe_test_1")
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
            store.rollback()
            return False
        finally:
            store.drop_view_if_exists("abe_test_v1")
            store.drop_table_if_exists("abe_test_1")

    def _test_sequence_type(store):
        store.drop_table_if_exists("abe_test_1")
        store.drop_sequence_if_exists("abe_test_1")

        try:
            store.ddl(
                """CREATE TABLE abe_test_1 (
                    abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY,
                    foo VARCHAR(10))""")
            store.create_sequence('abe_test_1')
            id1 = store.new_id('abe_test_1')
            id2 = store.new_id('abe_test_1')
            if int(id1) != int(id2):
                return True
            return False
        except store.module.DatabaseError, e:
            store.rollback()
            return False
        except Exception, e:
            store.rollback()
            return False
        finally:
            store.drop_table_if_exists("abe_test_1")
            try:
                store.drop_sequence("abe_test_1")
            except store.module.DatabaseError:
                store.rollback()

    def configure_limit_style(store):
        for val in ['native', 'emulated']:
            store.config['limit_style'] = val
            store._set_sql_flavour()
            if store._test_limit_style():
                store.log.info("limit_style=%s", val)
                return
        raise Exception("Can not emulate LIMIT.")

    def _test_limit_style(store):
        store.drop_table_if_exists("abe_test_1")
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
            store.rollback()
            return False
        finally:
            store.drop_table_if_exists("abe_test_1")

    def save_config(store):
        store.config['schema_version'] = SCHEMA_VERSION
        for name in store.config.keys():
            store.save_configvar(name)

    def save_configvar(store, name):
        store.sql("UPDATE configvar SET configvar_value = ?"
                  " WHERE configvar_name = ?", (store.config[name], name))
        if store.cursor.rowcount == 0:
            store.sql("INSERT INTO configvar (configvar_name, configvar_value)"
                      " VALUES (?, ?)", (name, store.config[name]))

    def set_configvar(store, name, value):
        store.config[name] = value
        store.save_configvar(name)

    def cache_block(store, block_id, height, prev_id, search_id):
        assert isinstance(block_id, int), block_id
        assert isinstance(height, int), height
        assert prev_id is None or isinstance(prev_id, int)
        assert search_id is None or isinstance(search_id, int)
        block = {
            'height':    height,
            'prev_id':   prev_id,
            'search_id': search_id}
        store._blocks[block_id] = block
        return block

    def _load_block(store, block_id):
        block = store._blocks.get(block_id)
        if block is None:
            row = store.selectrow("""
                SELECT block_height, prev_block_id, search_block_id
                  FROM block
                 WHERE block_id = ?""", (block_id,))
            if row is None:
                return None
            height, prev_id, search_id = row
            block = store.cache_block(
                block_id, int(height),
                None if prev_id is None else int(prev_id),
                None if search_id is None else int(search_id))
        return block

    def get_block_id_at_height(store, height, descendant_id):
        if height is None:
            return None
        while True:
            block = store._load_block(descendant_id)
            if block['height'] == height:
                return descendant_id
            descendant_id = block[
                'search_id'
                if util.get_search_height(block['height']) >= height else
                'prev_id']

    def is_descended_from(store, block_id, ancestor_id):
#        ret = store._is_descended_from(block_id, ancestor_id)
#        store.log.debug("%d is%s descended from %d", block_id, '' if ret else ' NOT', ancestor_id)
#        return ret
#    def _is_descended_from(store, block_id, ancestor_id):
        block = store._load_block(block_id)
        ancestor = store._load_block(ancestor_id)
        height = ancestor['height']
        return block['height'] >= height and \
            store.get_block_id_at_height(height, block_id) == ancestor_id

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

    def import_block(store, b, chain_ids=frozenset()):

        # Import new transactions.
        b['value_in'] = 0
        b['value_out'] = 0
        b['value_destroyed'] = 0
        tx_hash_array = []

        # In the common case, all the block's txins _are_ linked, and we
        # can avoid a query if we notice this.
        all_txins_linked = True

        for pos in xrange(len(b['transactions'])):
            tx = b['transactions'][pos]
            if 'hash' not in tx:
                tx['hash'] = util.double_sha256(tx['tx'])
            tx_hash_array.append(tx['hash'])
            tx['tx_id'] = store.tx_find_id_and_value(tx)

            if tx['tx_id']:
                all_txins_linked = False
            else:
                if store.commit_bytes == 0:
                    tx['tx_id'] = store.import_and_commit_tx(tx, pos == 0)
                else:
                    tx['tx_id'] = store.import_tx(tx, pos == 0)
                if tx['unlinked_count'] > 0:
                    all_txins_linked = False

            if tx['value_in'] is None:
                b['value_in'] = None
            elif b['value_in'] is not None:
                b['value_in'] += tx['value_in']
            b['value_out'] += tx['value_out']
            b['value_destroyed'] += tx['value_destroyed']

        # Get a new block ID.
        block_id = int(store.new_id("block"))
        b['block_id'] = block_id

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

        if prev_seconds is None:
            b['seconds'] = None
        else:
            b['seconds'] = prev_seconds + b['nTime'] - prev_nTime
        if prev_satoshis is None or prev_satoshis < 0 or b['value_in'] is None:
            # XXX Abuse this field to save work in adopt_orphans.
            b['satoshis'] = -1 - b['value_destroyed']
        else:
            b['satoshis'] = prev_satoshis + b['value_out'] - b['value_in'] \
                - b['value_destroyed']

        if prev_satoshis is None or prev_satoshis < 0:
            ss_created = None
            b['total_ss'] = None
        else:
            ss_created = prev_satoshis * (b['nTime'] - prev_nTime)
            b['total_ss'] = prev_total_ss + ss_created

        if b['height'] is None or b['height'] < 2:
            b['search_block_id'] = None
        else:
            b['search_block_id'] = store.get_block_id_at_height(
                util.get_search_height(int(b['height'])),
                None if prev_block_id is None else int(prev_block_id))

        # Insert the block table row.
        try:
            store.sql(
                """INSERT INTO block (
                    block_id, block_hash, block_version, block_hashMerkleRoot,
                    block_nTime, block_nBits, block_nNonce, block_height,
                    prev_block_id, block_chain_work, block_value_in,
                    block_value_out, block_total_satoshis,
                    block_total_seconds, block_total_ss, block_num_tx,
                    search_block_id
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )""",
                (block_id, store.hashin(b['hash']), store.intin(b['version']),
                 store.hashin(b['hashMerkleRoot']), store.intin(b['nTime']),
                 store.intin(b['nBits']), store.intin(b['nNonce']),
                 b['height'], prev_block_id,
                 store.binin_int(b['chain_work'], WORK_BITS),
                 store.intin(b['value_in']), store.intin(b['value_out']),
                 store.intin(b['satoshis']), store.intin(b['seconds']),
                 store.intin(b['total_ss']),
                 len(b['transactions']), b['search_block_id']))

        except store.module.DatabaseError:

            if store.commit_bytes == 0:
                # Rollback won't undo any previous changes, since we
                # always commit.
                store.rollback()
                # If the exception is due to another process having
                # inserted the same block, it is okay.
                row = store.selectrow("""
                    SELECT block_id, block_satoshi_seconds
                      FROM block
                     WHERE block_hash = ?""",
                    (store.hashin(b['hash']),))
                if row:
                    store.log.info("Block already inserted; block_id %d unsued",
                                   block_id)
                    b['block_id'] = int(row[0])
                    b['ss'] = None if row[1] is None else int(row[1])
                    store.offer_block_to_chains(b, chain_ids)
                    return

            # This is not an expected error, or our caller may have to
            # rewind a block file.  Let them deal with it.
            raise

        # List the block's transactions in block_tx.
        for tx_pos in xrange(len(b['transactions'])):
            tx = b['transactions'][tx_pos]
            store.sql("""
                INSERT INTO block_tx
                    (block_id, tx_id, tx_pos)
                VALUES (?, ?, ?)""",
                      (block_id, tx['tx_id'], tx_pos))
            store.log.info("block_tx %d %d", block_id, tx['tx_id'])

        if b['height'] is not None:
            store._populate_block_txin(block_id)

            if all_txins_linked or not store._has_unlinked_txins(block_id):
                b['ss_destroyed'] = store._get_block_ss_destroyed(
                    block_id, b['nTime'],
                    map(lambda tx: tx['tx_id'], b['transactions']))
                if ss_created is None or prev_ss is None:
                    b['ss'] = None
                else:
                    b['ss'] = prev_ss + ss_created - b['ss_destroyed']

                store.sql("""
                    UPDATE block
                       SET block_satoshi_seconds = ?,
                           block_ss_destroyed = ?
                     WHERE block_id = ?""",
                          (store.intin(b['ss']),
                           store.intin(b['ss_destroyed']),
                           block_id))
            else:
                b['ss_destroyed'] = None
                b['ss'] = None

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

        # offer_block_to_chains calls adopt_orphans, which propagates
        # block_height and other cumulative data to the blocks
        # attached above.
        store.offer_block_to_chains(b, chain_ids)

        return block_id

    def _populate_block_txin(store, block_id):
        # Create rows in block_txin.  In case of duplicate transactions,
        # choose the one with the lowest block ID.  XXX For consistency,
        # it should be the lowest height instead of block ID.
        for row in store.selectall("""
            SELECT txin.txin_id, MIN(obt.block_id)
              FROM block_tx bt
              JOIN txin ON (txin.tx_id = bt.tx_id)
              JOIN txout ON (txin.txout_id = txout.txout_id)
              JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
             WHERE bt.block_id = ?
             GROUP BY txin.txin_id""", (block_id,)):
            (txin_id, oblock_id) = row
            if store.is_descended_from(block_id, int(oblock_id)):
                store.sql("""
                    INSERT INTO block_txin (block_id, txin_id, out_block_id)
                    VALUES (?, ?, ?)""",
                          (block_id, txin_id, oblock_id))

    def _has_unlinked_txins(store, block_id):
        (unlinked_count,) = store.selectrow("""
            SELECT COUNT(1)
              FROM block_tx bt
              JOIN txin ON (bt.tx_id = txin.tx_id)
              JOIN unlinked_txin u ON (txin.txin_id = u.txin_id)
             WHERE bt.block_id = ?""", (block_id,))
        return unlinked_count > 0

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
        return block_ss_destroyed

    # Propagate cumulative values to descendant blocks.  Return info
    # about the longest chains containing b.  The returned dictionary
    # is keyed by the chain_id of a chain whose validation policy b
    # satisfies.  Each value is a pair (block, work) where block is
    # the best block descended from b in the given chain, and work is
    # the sum of orphan_work and the work between b and block.  Only
    # chains in chain_mask are considered.  Even if no known chain
    # contains b, this routine populates any descendant blocks'
    # cumulative statistics that are known for b and returns an empty
    # dictionary.
    def adopt_orphans(store, b, orphan_work, chain_ids, chain_mask):
        block_id = b['block_id']
        height = None if b['height'] is None else b['height'] + 1

        # If adding block b, b will not yet be in chain_candidate, so
        # we rely on the chain_ids argument.  If called recursively,
        # look up chain_ids in chain_candidate.
        if not chain_ids:
            if chain_mask:
                chain_mask = chain_mask.intersection(
                    store.find_chains_containing_block(block_id))
            chain_ids = chain_mask

        ret = {}
        for chain_id in chain_ids:
            ret[chain_id] = (b, orphan_work)

        for row in store.selectall("""
            SELECT bn.next_block_id, b.block_nBits,
                   b.block_value_out, b.block_value_in, b.block_nTime,
                   b.block_total_satoshis
              FROM block_next bn
              JOIN block b ON (bn.next_block_id = b.block_id)
             WHERE bn.block_id = ?""", (block_id,)):
            next_id, nBits, value_out, value_in, nTime, satoshis = row
            nBits = int(nBits)
            nTime = int(nTime)
            satoshis = None if satoshis is None else int(satoshis)
            new_work = util.calculate_work(orphan_work, nBits)

            if b['chain_work'] is None:
                chain_work = None
            else:
                chain_work = b['chain_work'] + new_work - orphan_work

            if value_in is None:
                value, count1, count2 = store.selectrow("""
                    SELECT SUM(txout.txout_value),
                           COUNT(1),
                           COUNT(txout.txout_value)
                      FROM block_tx bt
                      JOIN txin ON (bt.tx_id = txin.tx_id)
                      LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
                     WHERE bt.block_id = ?""", (next_id,))
                if count1 == count2 + 1:
                    value_in = int(value)
                else:
                    store.log.warning(
                        "not updating block %d value_in: %s != %s + 1",
                        next_id, repr(count1), repr(count2))
            else:
                value_in = int(value_in)
            generated = None if value_in is None else int(value_out - value_in)

            if b['seconds'] is None:
                seconds = None
                total_ss = None
            else:
                new_seconds = nTime - b['nTime']
                seconds = b['seconds'] + new_seconds
                if b['total_ss'] is None or b['satoshis'] is None:
                    total_ss = None
                else:
                    total_ss = b['total_ss'] + new_seconds * b['satoshis']

            if satoshis < 0 and b['satoshis'] is not None and \
                    b['satoshis'] >= 0 and generated is not None:
                satoshis += 1 + b['satoshis'] + generated

            if height is None or height < 2:
                search_block_id = None
            else:
                search_block_id = store.get_block_id_at_height(
                    util.get_search_height(height), int(block_id))

            store.sql("""
                UPDATE block
                   SET block_height = ?,
                       block_chain_work = ?,
                       block_value_in = ?,
                       block_total_seconds = ?,
                       block_total_satoshis = ?,
                       block_total_ss = ?,
                       search_block_id = ?
                 WHERE block_id = ?""",
                      (height, store.binin_int(chain_work, WORK_BITS),
                       store.intin(value_in),
                       store.intin(seconds), store.intin(satoshis),
                       store.intin(total_ss), search_block_id,
                       next_id))

            ss = None

            if height is not None:
                store.sql("""
                    UPDATE chain_candidate SET block_height = ?
                     WHERE block_id = ?""",
                    (height, next_id))

                store._populate_block_txin(int(next_id))

                if b['ss'] is None or store._has_unlinked_txins(next_id):
                    pass
                else:
                    tx_ids = map(
                        lambda row: row[0],
                        store.selectall("""
                            SELECT tx_id
                              FROM block_tx
                             WHERE block_id = ?""", (next_id,)))
                    destroyed = store._get_block_ss_destroyed(
                        next_id, nTime, tx_ids)
                    ss = b['ss'] + b['satoshis'] * (nTime - b['nTime']) \
                        - destroyed

                    store.sql("""
                        UPDATE block
                           SET block_satoshi_seconds = ?,
                               block_ss_destroyed = ?
                         WHERE block_id = ?""",
                              (store.intin(ss),
                               store.intin(destroyed),
                               next_id))

                if store.use_firstbits:
                    for (addr_vers,) in store.selectall("""
                        SELECT c.chain_address_version
                          FROM chain c
                          JOIN chain_candidate cc ON (c.chain_id = cc.chain_id)
                         WHERE cc.block_id = ?""", (next_id,)):
                        store.do_vers_firstbits(addr_vers, int(next_id))

            nb = {
                "block_id": next_id,
                "height": height,
                "chain_work": chain_work,
                "nTime": nTime,
                "seconds": seconds,
                "satoshis": satoshis,
                "total_ss": total_ss,
                "ss": ss}
            next_ret = store.adopt_orphans(nb, new_work, None, chain_mask)

            for chain_id in ret.keys():
                pair = next_ret[chain_id]
                if pair and pair[1] > ret[chain_id][1]:
                    ret[chain_id] = pair

        return ret

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
            count_in, value_in = store.selectrow("""
                SELECT COUNT(1), SUM(prevout.txout_value)
                  FROM txin
                  JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
                 WHERE txin.tx_id = ?""", (tx_id,))
            if (count_in or 0) < len(tx['txIn']):
                value_in = None
            tx['value_in'] = None if value_in is None else int(value_in)
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
        tx['unlinked_count'] = 0
        for pos in xrange(len(tx['txIn'])):
            txin = tx['txIn'][pos]
            txin_id = store.new_id("txin")

            if is_coinbase:
                txout_id = None
            else:
                txout_id, value = store.lookup_txout(
                    txin['prevout_hash'], txin['prevout_n'])
                if value is None:
                    tx['value_in'] = None
                elif tx['value_in'] is not None:
                    tx['value_in'] += value

            store.sql("""
                INSERT INTO txin (
                    txin_id, tx_id, txin_pos, txout_id""" + (""",
                    txin_scriptSig, txin_sequence""" if store.keep_scriptsig
                                                             else "") + """
                ) VALUES (?, ?, ?, ?""" + (", ?, ?" if store.keep_scriptsig
                                           else "") + """)""",
                      (txin_id, tx_id, pos, txout_id,
                       store.binin(txin['scriptSig']),
                       store.intin(txin['sequence'])) if store.keep_scriptsig
                      else (txin_id, tx_id, pos, txout_id))
            if not is_coinbase and txout_id is None:
                tx['unlinked_count'] += 1
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

    def import_and_commit_tx(store, tx, is_coinbase):
        try:
            tx_id = store.import_tx(tx, is_coinbase)
            store.commit()

        except store.module.DatabaseError:
            store.rollback()
            # Violation of tx_hash uniqueness?
            tx_id = store.tx_find_id_and_value(tx)
            if not tx_id:
                raise

        return tx_id

    def export_tx(store, tx_id=None, tx_hash=None, decimals=8):
        """Return a dict as seen by /rawtx or None if not found."""

        tx = {}

        if tx_id is not None:
            row = store.selectrow("""
                SELECT tx_hash, tx_version, tx_lockTime, tx_size
                  FROM tx
                 WHERE tx_id = ?
            """, (tx_id,))
            if row is None:
                return None
            tx['hash'] = store.hashout_hex(row[0])

        elif tx_hash is not None:
            row = store.selectrow("""
                SELECT tx_id, tx_version, tx_lockTime, tx_size
                  FROM tx
                 WHERE tx_hash = ?
            """, (store.hashin_hex(tx_hash),))
            if row is None:
                return None
            tx['hash'] = tx_hash
            tx_id = row[0]

        else:
            raise ValueError("export_tx requires either tx_id or tx_hash.")

        tx['ver']       = int(row[1])
        tx['lock_time'] = int(row[2])
        tx['size']      = int(row[3])

        tx['in'] = []
        for row in store.selectall("""
            SELECT
                COALESCE(tx.tx_hash, uti.txout_tx_hash),
                COALESCE(txout.txout_pos, uti.txout_pos)""" + (""",
                txin_scriptSig,
                txin_sequence""" if store.keep_scriptsig else "") + """
            FROM txin
            LEFT JOIN txout ON (txin.txout_id = txout.txout_id)
            LEFT JOIN tx ON (txout.tx_id = tx.tx_id)
            LEFT JOIN unlinked_txin uti ON (txin.txin_id = uti.txin_id)
            WHERE txin.tx_id = ?
            ORDER BY txin.txin_pos""", (tx_id,)):
            prevout_hash = row[0]
            prevout_n = row[1]
            if prevout_hash is None:
                prev_out = {
                    'hash': "0" * 64,  # XXX should store this?
                    'n': 0xffffffff}   # XXX should store this?
            else:
                prev_out = {
                    'hash': store.hashout_hex(prevout_hash),
                    'n': int(prevout_n)}
            txin = {'prev_out': prev_out}
            if store.keep_scriptsig:
                txin['raw_scriptSig'] = store.binout_hex(row[2])
                txin['sequence'] = store.binout_hex(row[3])
            tx['in'].append(txin)
        tx['vin_sz'] = len(tx['in'])

        tx['out'] = []
        for satoshis, scriptPubKey in store.selectall("""
            SELECT txout_value, txout_scriptPubKey
              FROM txout
             WHERE tx_id = ?
            ORDER BY txout_pos""", (tx_id,)):

            coin = 10 ** decimals
            satoshis = int(satoshis)
            integer = satoshis / coin
            frac = satoshis % coin
            tx['out'].append({
                    'value': ("%%d.%%0%dd" % (decimals,)) % (integer, frac),
                    'raw_scriptPubKey': store.binout_hex(scriptPubKey)})
        tx['vout_sz'] = len(tx['out'])

        return tx

    # Called to indicate that the given block has the correct magic
    # number and policy for the given chains.  Updates CHAIN_CANDIDATE
    # and CHAIN.CHAIN_LAST_BLOCK_ID as appropriate.
    def offer_block_to_chains(store, b, chain_ids):
        b['top'] = store.adopt_orphans(b, 0, chain_ids, chain_ids)
        for chain_id in chain_ids:
            store._offer_block_to_chain(b, chain_id)

    def _offer_block_to_chain(store, b, chain_id):
        if b['chain_work'] is None:
            in_longest = 0
        else:
            # Do we produce a chain longer than the current chain?
            # Query whether the new block (or its tallest descendant)
            # beats the current chain_last_block_id.  Also check
            # whether the current best is our top, which indicates
            # this block is in longest; this can happen in database
            # repair scenarios.
            top = b['top'][chain_id][0]
            row = store.selectrow("""
                SELECT b.block_id, b.block_height, b.block_chain_work
                  FROM block b, chain c
                 WHERE c.chain_id = ?
                   AND b.block_id = c.chain_last_block_id""", (chain_id,))
            if row:
                loser_id, loser_height, loser_work = row
                if loser_id <> top['block_id'] and \
                        store.binout_int(loser_work) >= top['chain_work']:
                    row = None
            if row:
                # New longest chain.
                in_longest = 1
                to_connect = []
                to_disconnect = []
                winner_id = top['block_id']
                winner_height = top['height']
                while loser_height > winner_height:
                    to_disconnect.insert(0, loser_id)
                    loser_id = store.get_prev_block_id(loser_id)
                    loser_height -= 1
                while winner_height > loser_height:
                    to_connect.insert(0, winner_id)
                    winner_id = store.get_prev_block_id(winner_id)
                    winner_height -= 1
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

        if in_longest > 0:
            store.sql("""
                UPDATE chain
                   SET chain_last_block_id = ?
                 WHERE chain_id = ?""", (top['block_id'], chain_id))

        if store.use_firstbits and b['height'] is not None:
            (addr_vers,) = store.selectrow("""
                SELECT chain_address_version
                  FROM chain
                 WHERE chain_id = ?""", (chain_id,))
            store.do_vers_firstbits(addr_vers, b['block_id'])

    def find_next_blocks(store, block_id):
        ret = []
        for row in store.selectall(
            "SELECT next_block_id FROM block_next WHERE block_id = ?",
            (block_id,)):
            ret.append(row[0])
        return ret

    def find_chains_containing_block(store, block_id):
        ret = []
        for row in store.selectall(
            "SELECT chain_id FROM chain_candidate WHERE block_id = ?",
            (block_id,)):
            ret.append(row[0])
        return frozenset(ret)

    def get_prev_block_id(store, block_id):
        return store.selectrow(
            "SELECT prev_block_id FROM block WHERE block_id = ?",
            (block_id,))[0]

    def disconnect_block(store, block_id, chain_id):
        store.sql("""
            UPDATE chain_candidate
               SET in_longest = 0
             WHERE block_id = ? AND chain_id = ?""",
                  (block_id, chain_id))

    def connect_block(store, block_id, chain_id):
        store.sql("""
            UPDATE chain_candidate
               SET in_longest = 1
             WHERE block_id = ? AND chain_id = ?""",
                  (block_id, chain_id))

    def lookup_txout(store, tx_hash, txout_pos):
        row = store.selectrow("""
            SELECT txout.txout_id, txout.txout_value
              FROM txout, tx
             WHERE txout.tx_id = tx.tx_id
               AND tx.tx_hash = ?
               AND txout.txout_pos = ?""",
                  (store.hashin(tx_hash), txout_pos))
        return (None, None) if row is None else (row[0], int(row[1]))

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
                store.log.exception("Failed to catch up %s", dircfg)
                store.rollback()

    # Load all blocks starting at the current file and offset.
    def catch_up_dir(store, dircfg):
        def open_blkfile():
            store._refresh_dircfg(dircfg)
            filename = store.blkfile_name(dircfg)
            ds = BCDataStream.BCDataStream()
            file = open(filename, "rb")
            try:
                ds.map_file(file, 0)
            except:
                # mmap can fail on an empty file, but empty files are okay.
                file.seek(0, os.SEEK_END)
                if file.tell() == 0:
                    ds.input = ""
                    ds.read_cursor = 0
                else:
                    ds.map_file(file, 0)
            finally:
                file.close()
            return ds

        try:
            ds = open_blkfile()
        except IOError, e:
            store.log.warning("Skipping datadir %s: %s", dircfg['dirname'], e)
            return

        while True:
            try:
                store.import_blkdat(dircfg, ds)
            except:
                store.log.warning("Exception at %d" % ds.read_cursor)
                raise
            finally:
                try:
                    ds.close_file()
                except:
                    pass

            # Try another file.
            dircfg['blkfile_number'] += 1
            try:
                ds = open_blkfile()
            except IOError, e:
                if e.errno != errno.ENOENT:
                    raise
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
                    store.log.info("Skipped %d NUL bytes at block end",
                                   ds.read_cursor - offset)
                    continue

                filename = store.blkfile_name(dircfg)
                store.log.error(
                    "Chain not found for magic number %s in block file %s at"
                    " offset %d.  If file contents have changed, consider"
                    " forcing a rescan: UPDATE datadir SET blkfile_number=1,"
                    " blkfile_offset=0 WHERE dirname='%s'",
                    repr(magic), filename, offset, dircfg['dirname'])
                ds.read_cursor = offset
                break

            length = ds.read_int32()
            if ds.read_cursor + length > len(ds.input):
                store.log.debug("incomplete block of length %d chain %d",
                                length, chain_id)
                ds.read_cursor = offset
                break
            end = ds.read_cursor + length

            hash = util.double_sha256(
                ds.input[ds.read_cursor : ds.read_cursor + 80])
            # XXX should decode target and check hash against it to
            # avoid loading garbage data.  But not for merged-mined or
            # CPU-mined chains that use different proof-of-work
            # algorithms.  Time to resurrect policy_id?

            block_row = store.selectrow("""
                SELECT block_id, block_height, block_chain_work,
                       block_nTime, block_total_seconds,
                       block_total_satoshis, block_satoshi_seconds
                  FROM block
                 WHERE block_hash = ?
            """, (store.hashin(hash),))

            if block_row:
                # Block header already seen.  Don't import the block,
                # but try to add it to the chain.
                if chain_id is not None:
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
                        store.log.info("block %d already in chain %d",
                                       b['block_id'], chain_id)
                        b = None
                    else:
                        if b['height'] == 0:
                            b['hashPrev'] = GENESIS_HASH_PREV
                        else:
                            b['hashPrev'] = 'dummy'  # Fool adopt_orphans.
                        store.offer_block_to_chains(b, frozenset([chain_id]))
            else:
                b = store.parse_block(ds, chain_id, magic, length)
                b["hash"] = hash
                chain_ids = frozenset([] if chain_id is None else [chain_id])
                store.import_block(b, chain_ids = chain_ids)
                if ds.read_cursor != end:
                    store.log.debug("Skipped %d bytes at block end",
                                    end - ds.read_cursor)

            ds.read_cursor = end

            bytes_done += length
            if bytes_done >= store.commit_bytes:
                store.log.debug("commit")
                store.save_blkfile_offset(dircfg, ds.read_cursor)
                store.commit()
                store._refresh_dircfg(dircfg)
                bytes_done = 0

        if bytes_done > 0:
            store.save_blkfile_offset(dircfg, ds.read_cursor)
            store.commit()

    def parse_block(store, ds, chain_id=None, magic=None, length=None):
        d = deserialize.parse_BlockHeader(ds)
        if d['version'] & (1 << 8):
            if chain_id in store.no_bit8_chain_ids:
                store.log.debug(
                    "Ignored bit8 in version 0x%08x of chain_id %d"
                    % (d['version'], chain_id))
            else:
                d['auxpow'] = deserialize.parse_AuxPow(ds)
        d['transactions'] = []
        nTransactions = ds.read_compact_size()
        for i in xrange(nTransactions):
            d['transactions'].append(deserialize.parse_Transaction(ds))
        return d

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

    def get_block_number(store, chain_id):
        (height,) = store.selectrow("""
            SELECT MAX(block_height)
              FROM chain_candidate
             WHERE chain_id = ?
               AND in_longest = 1""", (chain_id,))
        return -1 if height is None else int(height)

    def get_target(store, chain_id):
        rows = store.selectall("""
            SELECT b.block_nBits
              FROM block b
              JOIN chain c ON (b.block_id = c.chain_last_block_id)
             WHERE c.chain_id = ?""", (chain_id,))
        return util.calculate_target(int(rows[0][0])) if rows else None

    def firstbits_full(store, version, hash):
        """
        Return the address in lowercase.  An initial substring of this
        will become the firstbits.
        """
        return util.hash_to_address(version, hash).lower()

    def insert_firstbits(store, pubkey_id, block_id, addr_vers, fb):
        store.sql("""
            INSERT INTO abe_firstbits (
                pubkey_id, block_id, address_version, firstbits
            )
            VALUES (?, ?, ?, ?)""",
                  (pubkey_id, block_id, addr_vers, fb))

    def cant_do_firstbits(store, addr_vers, block_id, pubkey_id):
        store.log.info(
            "No firstbits for pubkey_id %d, block_id %d, version '%s'",
            pubkey_id, block_id, store.binout_hex(addr_vers))
        store.insert_firstbits(pubkey_id, block_id, addr_vers, '')

    def do_firstbits(store, addr_vers, block_id, fb, ids, full):
        """
        Insert the firstbits that start with fb using addr_vers and
        are first seen in block_id.  Return the count of rows
        inserted.

        fb -- string, not a firstbits using addr_vers in any ancestor
        of block_id
        ids -- set of ids of all pubkeys first seen in block_id whose
        firstbits start with fb
        full -- map from pubkey_id to full firstbits
        """

        if len(ids) <= 1:
            for pubkey_id in ids:
                store.insert_firstbits(pubkey_id, block_id, addr_vers, fb)
            return len(ids)

        pubkeys = {}
        for pubkey_id in ids:
            s = full[pubkey_id]
            if s == fb:
                store.cant_do_firstbits(addr_vers, block_id, pubkey_id)
                continue
            fb1 = fb + s[len(fb)]
            ids1 = pubkeys.get(fb1)
            if ids1 is None:
                ids1 = set()
                pubkeys[fb1] = ids1
            ids1.add(pubkey_id)

        count = 0
        for fb1, ids1 in pubkeys.iteritems():
            count += store.do_firstbits(addr_vers, block_id, fb1, ids1, full)
        return count

    def do_vers_firstbits(store, addr_vers, block_id):
        """
        Create new firstbits records for block and addr_vers.  All
        ancestor blocks must have their firstbits already recorded.
        """

        address_version = store.binout(addr_vers)
        pubkeys = {}  # firstbits to set of pubkey_id
        full    = {}  # pubkey_id to full firstbits, or None if old

        for pubkey_id, pubkey_hash, oblock_id in store.selectall("""
            SELECT DISTINCT
                   pubkey.pubkey_id,
                   pubkey.pubkey_hash,
                   fb.block_id
              FROM block b
              JOIN block_tx bt ON (b.block_id = bt.block_id)
              JOIN txout ON (bt.tx_id = txout.tx_id)
              JOIN pubkey ON (txout.pubkey_id = pubkey.pubkey_id)
              LEFT JOIN abe_firstbits fb ON (
                       fb.address_version = ?
                   AND fb.pubkey_id = pubkey.pubkey_id)
             WHERE b.block_id = ?""", (addr_vers, block_id)):

            pubkey_id = int(pubkey_id)

            if (oblock_id is not None and
                store.is_descended_from(block_id, int(oblock_id))):
                full[pubkey_id] = None

            if pubkey_id in full:
                continue

            full[pubkey_id] = store.firstbits_full(address_version,
                                                   store.binout(pubkey_hash))

        for pubkey_id, s in full.iteritems():
            if s is None:
                continue

            # This is the pubkey's first appearance in the chain.
            # Find the longest match among earlier firstbits.
            longest, longest_id = 0, None
            substrs = [s[0:(i+1)] for i in xrange(len(s))]
            for ancestor_id, fblen, o_pubkey_id in store.selectall("""
                SELECT block_id, LENGTH(firstbits), pubkey_id
                  FROM abe_firstbits fb
                 WHERE address_version = ?
                   AND firstbits IN (?""" + (",?" * (len(s)-1)) + """
                       )""", tuple([addr_vers] + substrs)):
                if fblen > longest and store.is_descended_from(
                    block_id, int(ancestor_id)):
                    longest, longest_id = fblen, o_pubkey_id

            # If necessary, extend the new fb to distinguish it from
            # the longest match.
            if longest_id is not None:
                (o_hash,) = store.selectrow(
                    "SELECT pubkey_hash FROM pubkey WHERE pubkey_id = ?",
                    (longest_id,))
                o_fb = store.firstbits_full(
                    address_version, store.binout(o_hash))
                max_len = min(len(s), len(o_fb))
                while longest < max_len and s[longest] == o_fb[longest]:
                    longest += 1

            if longest == len(s):
                store.cant_do_firstbits(addr_vers, block_id, pubkey_id)
                continue

            fb = s[0 : (longest + 1)]
            ids = pubkeys.get(fb)
            if ids is None:
                ids = set()
                pubkeys[fb] = ids
            ids.add(pubkey_id)

        count = 0
        for fb, ids in pubkeys.iteritems():
            count += store.do_firstbits(addr_vers, block_id, fb, ids, full)
        return count

    def firstbits_to_addresses(store, fb, chain_id=None):
        dbfb = fb.lower()
        ret = []
        bind = [fb[0:(i+1)] for i in xrange(len(fb))]
        if chain_id is not None:
            bind.append(chain_id)

        for dbhash, vers in store.selectall("""
            SELECT pubkey.pubkey_hash,
                   fb.address_version
              FROM abe_firstbits fb
              JOIN pubkey ON (fb.pubkey_id = pubkey.pubkey_id)
              JOIN chain_candidate cc ON (cc.block_id = fb.block_id)
             WHERE fb.firstbits IN (?""" + (",?" * (len(fb)-1)) + """)""" + ( \
                "" if chain_id is None else """
               AND cc.chain_id = ?"""), tuple(bind)):
            address = util.hash_to_address(store.binout(vers),
                                           store.binout(dbhash))
            if address.lower().startswith(dbfb):
                ret.append(address)

        if len(ret) == 0 or (len(ret) > 1 and fb in ret):
            ret = [fb]  # assume exact address match

        return ret

    def get_firstbits(store, address_version=None, db_pubkey_hash=None,
                      chain_id=None):
        """
        Return address's firstbits, or the longest of multiple
        firstbits values if chain_id is not given, or None if address
        has not appeared, or the empty string if address has appeared
        but has no firstbits.
        """
        vers, dbhash = store.binin(address_version), db_pubkey_hash
        rows = store.selectall("""
            SELECT fb.firstbits
              FROM abe_firstbits fb
              JOIN pubkey ON (fb.pubkey_id = pubkey.pubkey_id)
              JOIN chain_candidate cc ON (fb.block_id = cc.block_id)
             WHERE cc.in_longest = 1
               AND fb.address_version = ?
               AND pubkey.pubkey_hash = ?""" + (
                "" if chain_id is None else """
               AND cc.chain_id = ?"""),
                               (vers, dbhash) if chain_id is None else
                               (vers, dbhash, chain_id))
        if not rows:
            return None

        ret = ""
        for (fb,) in rows:
            if len(fb) > len(ret):
                ret = fb
        return ret

def new(args):
    return DataStore(args)
