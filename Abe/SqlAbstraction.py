# Copyright(C) 2011,2012,2013 by John Tobey <jtobey@john-edwin-tobey.org>

# sql.py: feature-detecting, SQL-transforming database abstraction layer

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

import re
import logging

CONFIG_DEFAULTS = {
    "binary_type":        None,
    "int_type":           None,
}

NO_CLOB = 'BUG_NO_CLOB'
STMT_RE = re.compile(r"([^']+)((?:'[^']*')?)")

class SqlAbstraction(object):

    """
    Database abstraction class based on DB-API 2 and standard SQL with
    workarounds to support SQLite3, PostgreSQL/psycopg2, MySQL,
    Oracle, ODBC, and IBM DB2.
    """

    # XXX Consider moving conn and cursor into sql during configure.
    # XXX Abstract out the "abe_" prefix on database object names.

    def __init__(sql, module, config=None):
        sql.module = module
        sql.config = config or {}
        sql.log = logging.getLogger(__name__)
        sql._set_flavour()
        sql.sqllog = logging.getLogger(__name__ + ".sql")

    def _set_flavour(sql):
        def identity(x):
            return x
        transform = identity
        transform_stmt = sql._transform_stmt
        selectall = sql._selectall

        if sql.module.paramstyle in ('format', 'pyformat'):
            transform = sql._qmark_to_format(transform)
        elif sql.module.paramstyle == 'named':
            transform_stmt = sql._qmark_to_named(transform_stmt)
        elif sql.module.paramstyle != 'qmark':
            sql.log.warning("Database parameter style is "
                            "%s, trying qmark", sql.module.paramstyle)
            pass

        # Binary I/O with the database.
        # Reversed versions exist for Bitcoin hashes; since the
        # protocol treats them as 256-bit integers and represents them
        # as little endian, we have to reverse them in hex to satisfy
        # human expectations.
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

        val = sql.config.get('binary_type')

        if val in (None, 'str', "binary"):
            binin       = identity
            binin_hex   = from_hex
            binout      = identity
            binout_hex  = to_hex
            revin       = rev
            revin_hex   = from_hex
            revout      = rev
            revout_hex  = to_hex

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
            revin       = lambda x: to_btype(rev(x))
            revin_hex   = lambda x: to_btype(from_hex(x))
            revout      = rev
            revout_hex  = to_hex

            if val == "pg-bytea":
                transform_stmt = sql._binary_as_bytea(transform_stmt)

        elif val == "hex":
            transform = sql._binary_as_hex(transform)
            binin       = to_hex
            binin_hex   = identity
            binout      = from_hex
            binout_hex  = identity
            revin       = to_hex_rev
            revin_hex   = identity
            revout      = from_hex_rev
            revout_hex  = identity

        else:
            raise Exception("Unsupported binary-type %s" % (val,))

        val = sql.config.get('int_type')
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

        else:
            raise Exception("Unsupported int-type %s" % (val,))

        val = sql.config.get('sequence_type')
        if val in (None, 'update'):
            new_id = lambda cursor, key: sql._new_id_update(cursor, key)
            create_sequence = lambda conn, cursor, key: \
                sql._create_sequence_update(conn, cursor, key)
            drop_sequence = lambda conn, cursor, key: \
                sql._drop_sequence_update(conn, cursor, key)

        elif val == 'mysql':
            new_id = lambda cursor, key: sql._new_id_mysql(cursor, key)
            create_sequence = lambda conn, cursor, key: \
                sql._create_sequence_mysql(conn, cursor, key)
            drop_sequence = lambda conn, cursor, key: \
                sql._drop_sequence_mysql(conn, cursor, key)

        else:
            create_sequence = lambda conn, cursor, key: \
                sql._create_sequence(conn, cursor, key)
            drop_sequence = lambda conn, cursor, key: \
                sql._drop_sequence(conn, cursor, key)

            if val == 'oracle':
                new_id = lambda cursor, key: sql._new_id_oracle(cursor, key)
            elif val == 'nvf':
                new_id = lambda cursor, key: sql._new_id_nvf(cursor, key)
            elif val == 'postgres':
                new_id = lambda cursor, key: sql._new_id_postgres(cursor, key)
            elif val == 'db2':
                new_id = lambda cursor, key: sql._new_id_db2(cursor, key)
                create_sequence = lambda conn, cursor, key: \
                    sql._create_sequence_db2(conn, cursor, key)
            else:
                raise Exception("Unsupported sequence-type %s" % (val,))

        # Convert Oracle LOB to str.
        if hasattr(sql.module, "LOB") and isinstance(sql.module.LOB, type):
            def fix_lob(fn):
                def ret(x):
                    return None if x is None else fn(str(x))
                return ret
            binout = fix_lob(binout)
            binout_hex = fix_lob(binout_hex)

        val = sql.config.get('limit_style')
        if val in (None, 'native'):
            pass
        elif val == 'emulated':
            selectall = sql.emulate_limit(selectall)

        transform_stmt = sql._append_table_epilogue(transform_stmt)

        transform = sql._fallback_to_lob(transform)
        transform = sql._fallback_to_approximate(transform)

        sql.transform_chunk = transform
        sql.transform_stmt = transform_stmt
        sql.selectall = selectall
        sql._cache = {}

        sql.binin       = binin
        sql.binin_hex   = binin_hex
        sql.binout      = binout
        sql.binout_hex  = binout_hex
        sql.revin       = revin
        sql.revin_hex   = revin_hex
        sql.revout      = revout
        sql.revout_hex  = revout_hex

        # Might reimplement these someday...
        def binout_int(x):
            if x is None:
                return None
            return int(binout_hex(x), 16)
        def binin_int(x, bits):
            if x is None:
                return None
            return binin_hex(("%%0%dx" % (bits / 4)) % x)
        sql.binout_int  = binout_int
        sql.binin_int   = binin_int

        sql.intin       = intin
        sql.new_id      = new_id
        sql.create_sequence = create_sequence
        sql.drop_sequence = drop_sequence

    # Run transform_chunk on each chunk between string literals.
    def _transform_stmt(sql, stmt):
        def transform_chunk(match):
            return sql.transform_chunk(match.group(1)) + match.group(2)
        return STMT_RE.sub(transform_chunk, stmt)

    # Convert standard placeholders to Python "format" style.
    def _qmark_to_format(sql, fn):
        def ret(chunk):
            return fn(chunk.replace('%', '%%').replace("?", "%s"))
        return ret

    # Convert standard placeholders to Python "named" style.
    def _qmark_to_named(sql, fn):
        patt = re.compile(r"\?")
        def ret(stmt):
            i = [0]
            def newname(match):
                i[0] += 1
                return ":p%d" % (i[0],)
            def transform_chunk(match):
                return patt.sub(newname, match.group(1)) + match.group(2)
            return fn(STMT_RE.sub(transform_chunk, stmt))
        return ret

    # Convert the standard BINARY type to a hex string for databases
    # and drivers that don't support BINARY.
    def _binary_as_hex(sql, fn):
        patt = re.compile(r"\b((?:VAR)?)BINARY\s*\(\s*([0-9]+)\s*\)")
        x_patt = re.compile(r"X\z")
        def fixup(match):
            return (match.group(1) + "CHAR(" +
                    str(int(match.group(2)) * 2) + ")")
        def ret(chunk):
            return fn(x_patt.sub("", patt.sub(fixup, chunk)))
        return ret

    # Convert the standard BINARY type to the PostgreSQL BYTEA type.
    def _binary_as_bytea(sql, fn):
        type_patt = re.compile("((?:VAR)?)BINARY\\(([0-9]+)\\)")
        lit_patt = re.compile("X'((?:[0-9a-fA-F][0-9a-fA-F])*)'")
        def ret(stmt):
            def transform_chunk(match):
                ret = type_patt.sub("BYTEA", match.group(1))
                if match.group(1).endswith('X') and match.group(2) != '':
                    ret = ret[:-1] + "'"
                    for i in match.group(2)[1:-1].decode('hex'):
                        ret += r'\\%03o' % ord(i)
                    ret += "'::bytea"
                else:
                    ret += match.group(2)
                return ret
            return fn(STMT_RE.sub(transform_chunk, stmt))
        return ret

    # Converts VARCHAR types that are too long to CLOB or similar.
    def _fallback_to_lob(sql, fn):
        if sql.config.get('max_varchar') is None:
            return fn
        max_varchar = int(sql.config['max_varchar'])

        if sql.config.get('clob_type') is None:
            return fn
        clob_type = sql.config['clob_type']

        patt = re.compile("VARCHAR\\(([0-9]+)\\)")

        def fixup(match):
            width = int(match.group(1))
            if width > max_varchar and clob_type != NO_CLOB:
                return clob_type
            return match.group()

        def ret(stmt):
            return fn(patt.sub(fixup, stmt))

        return ret

    # Convert high-precision NUMERIC and DECIMAL types to DOUBLE PRECISION
    # to avoid integer overflow with SQLite.
    def _fallback_to_approximate(sql, fn):
        if sql.config.get('max_precision') is None:
            return fn

        max_precision = int(sql.config['max_precision'])
        patt = re.compile(
            r"\b(?:NUMERIC|DECIMAL)\s*\(\s*([0-9]+)\s*(?:,.*?)?\)")

        def fixup(match):
            precision = int(match.group(1))
            if precision > max_precision:
                return "DOUBLE PRECISION"
            return match.group()

        def ret(stmt):
            return fn(patt.sub(fixup, stmt))

        return ret

    def emulate_limit(sql, selectall):
        limit_re = re.compile(r"(.*)\bLIMIT\s+(\?|\d+)\s*\Z", re.DOTALL)
        def ret(cursor, stmt, params=()):
            match = limit_re.match(sql.transform_stmt_cached(stmt))
            if match:
                if match.group(2) == '?':
                    n = params[-1]
                    params = params[:-1]
                else:
                    n = int(match.group(2))
                cursor.execute(match.group(1), params)
                return [ cursor.fetchone() for i in xrange(n) ]
            return selectall(cursor, stmt, params)
        return ret

    def _append_table_epilogue(sql, fn):
        epilogue = sql.config.get('create_table_epilogue', "")
        if epilogue == "":
            return fn

        patt = re.compile(r"\s*CREATE\s+TABLE\b")

        def ret(stmt):
            if patt.match(stmt):
                stmt += epilogue
            return fn(stmt)
        return ret

    def transform_stmt_cached(sql, stmt):
        cached = sql._cache.get(stmt)
        if cached is None:
            cached = sql.transform_stmt(stmt)
            sql._cache[stmt] = cached
        return cached

    def sql(sql, cursor, stmt, params=()):
        cached = sql.transform_stmt_cached(stmt)
        sql.sqllog.info("EXEC: %s %s", cached, params)
        try:
            cursor.execute(cached, params)
        except Exception, e:
            sql.sqllog.info("EXCEPTION: %s", e)
            raise

    def ddl(sql, conn, cursor, stmt):
        stmt = sql.transform_stmt(stmt)
        sql.sqllog.info("DDL: %s", stmt)
        try:
            cursor.execute(stmt)
        except Exception, e:
            sql.sqllog.info("EXCEPTION: %s", e)
            raise
        if sql.config.get('ddl_implicit_commit') == 'false':
            conn.commit()

    def selectrow(sql, cursor, stmt, params=()):
        sql.sql(cursor, stmt, params)
        ret = cursor.fetchone()
        sql.sqllog.debug("FETCH: %s", ret)
        return ret

    def _selectall(sql, cursor, stmt, params=()):
        sql.sql(cursor, stmt, params)
        ret = cursor.fetchall()
        sql.sqllog.debug("FETCHALL: %s", ret)
        return ret

    def _new_id_update(sql, cursor, key):
        """
        Allocate a synthetic identifier by updating a table.
        """
        while True:
            row = sql.selectrow(
                cursor,
                "SELECT nextid FROM abe_sequences WHERE sequence_key = ?",
                (key,))
            if row is None:
                raise Exception("Sequence %s does not exist" % key)

            ret = row[0]
            sql.sql(cursor,
                    "UPDATE abe_sequences SET nextid = nextid + 1"
                    " WHERE sequence_key = ? AND nextid = ?",
                    (key, ret))
            if cursor.rowcount == 1:
                return ret
            sql.log.info('Contention on abe_sequences %s:%d', key, ret)

    def _get_sequence_initial_value(sql, cursor, key):
        (ret,) = sql.selectrow(cursor, "SELECT MAX(" + key + "_id) FROM " + key)
        ret = 1 if ret is None else ret + 1
        return ret

    def _create_sequence_update(sql, conn, cursor, key):
        sql.commit(conn)
        ret = sql._get_sequence_initial_value(cursor, key)
        try:
            sql.sql(cursor,
                    "INSERT INTO abe_sequences (sequence_key, nextid)"
                    " VALUES (?, ?)", (key, ret))
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            try:
                sql.ddl(conn, cursor, """CREATE TABLE abe_sequences (
                    sequence_key VARCHAR(100) NOT NULL PRIMARY KEY,
                    nextid NUMERIC(30)
                )""")
            except:
                sql.rollback(conn)
                raise e
            sql.sql(cursor,
                    "INSERT INTO abe_sequences (sequence_key, nextid)"
                    " VALUES (?, ?)", (key, ret))

    def _drop_sequence_update(sql, conn, cursor, key):
        sql.commit(conn)
        sql.sql(cursor,
                "DELETE FROM abe_sequences WHERE sequence_key = ?", (key,))
        sql.commit(conn)

    def _new_id_oracle(sql, cursor, key):
        (ret,) = sql.selectrow(cursor,
                               "SELECT " + key + "_seq.NEXTVAL FROM DUAL")
        return ret

    def _create_sequence(sql, conn, cursor, key):
        sql.ddl(conn, cursor, "CREATE SEQUENCE %s_seq START WITH %d"
                % (key, sql._get_sequence_initial_value(cursor, key)))

    def _drop_sequence(sql, conn, cursor, key):
        sql.ddl(conn, cursor, "DROP SEQUENCE %s_seq" % (key,))

    def _new_id_nvf(sql, cursor, key):
        (ret,) = sql.selectrow(cursor, "SELECT NEXT VALUE FOR " + key + "_seq")
        return ret

    def _new_id_postgres(sql, cursor, key):
        (ret,) = sql.selectrow(cursor, "SELECT NEXTVAL('" + key + "_seq')")
        return ret

    def _create_sequence_db2(sql, conn, cursor, key):
        sql.commit(conn)
        try:
            rows = sql.selectall(cursor, "SELECT 1 FROM abe_dual")
            if len(rows) != 1:
                sql.sql(cursor, "INSERT INTO abe_dual(x) VALUES ('X')")
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            sql.drop_table_if_exists(conn, cursor, 'abe_dual')
            sql.ddl(conn, cursor, "CREATE TABLE abe_dual (x CHAR(1))")
            sql.sql(cursor, "INSERT INTO abe_dual(x) VALUES ('X')")
            sql.log.info("Created silly table abe_dual")
        sql._create_sequence(conn, cursor, key)

    def _new_id_db2(sql, cursor, key):
        (ret,) = sql.selectrow(cursor, "SELECT NEXTVAL FOR " + key + "_seq"
                               " FROM abe_dual")
        return ret

    def _create_sequence_mysql(sql, conn, cursor, key):
        sql.ddl(conn, cursor,
                "CREATE TABLE %s_seq (id BIGINT AUTO_INCREMENT PRIMARY KEY)"
                " AUTO_INCREMENT=%d"
                % (key, sql._get_sequence_initial_value(cursor, key)))

    def _drop_sequence_mysql(sql, conn, cursor, key):
        sql.ddl(conn, cursor, "DROP TABLE %s_seq" % (key,))

    def _new_id_mysql(sql, cursor, key):
        sql.sql(cursor, "INSERT INTO " + key + "_seq () VALUES ()")
        (ret,) = sql.selectrow(cursor, "SELECT LAST_INSERT_ID()")
        if ret % 1000 == 0:
            sql.sql(cursor, "DELETE FROM " + key + "_seq WHERE id < ?", (ret,))
        return ret

    def commit(sql, conn):
        sql.sqllog.info("COMMIT")
        conn.commit()

    def rollback(sql, conn):
        sql.sqllog.info("ROLLBACK")
        conn.rollback()

    def close(sql, conn):
        sql.sqllog.info("CLOSE")
        conn.close()

    def configure(sql, conn, cursor):
        sql.configure_ddl_implicit_commit(conn, cursor)
        sql.configure_create_table_epilogue(conn, cursor)
        sql.configure_max_varchar(conn, cursor)
        sql.configure_max_precision(conn, cursor)
        sql.configure_clob_type(conn, cursor)
        sql.configure_binary_type(conn, cursor)
        sql.configure_int_type(conn, cursor)
        sql.configure_sequence_type(conn, cursor)
        sql.configure_limit_style(conn, cursor)

        return sql.config

    def configure_binary_type(sql, conn, cursor):
        defaults = ['binary', 'bytearray', 'buffer', 'hex', 'pg-bytea']
        tests = (defaults
                 if sql.config.get('binary_type') is None else
                 [ sql.config['binary_type'] ])

        for val in tests:
            sql.config['binary_type'] = val
            sql._set_flavour()
            if sql._test_binary_type(conn, cursor):
                sql.log.info("binary_type=%s", val)
                return

        raise Exception(
            "No known binary data representation works"
            if len(tests) > 1 else
            "Binary type " + tests[0] + " fails test")

    def configure_int_type(sql, conn, cursor):
        defaults = ['int', 'decimal', 'str']
        tests = (defaults if sql.config.get('int_type') is None else
                 [ sql.config['int_type'] ])

        for val in tests:
            sql.config['int_type'] = val
            sql._set_flavour()
            if sql._test_int_type(conn, cursor):
                sql.log.info("int_type=%s", val)
                return
        raise Exception(
            "No known large integer representation works"
            if len(tests) > 1 else
            "Integer type " + tests[0] + " fails test")

    def configure_sequence_type(sql, conn, cursor):
        for val in ['nvf', 'oracle', 'postgres', 'mysql', 'db2', 'update']:
            sql.config['sequence_type'] = val
            sql._set_flavour()
            if sql._test_sequence_type(conn, cursor):
                sql.log.info("sequence_type=%s", val)
                return
        raise Exception("No known sequence type works")

    def _drop_if_exists(sql, conn, cursor, otype, name):
        try:
            sql.sql(cursor, "DROP " + otype + " " + name)
            sql.commit(conn)
        except sql.module.DatabaseError:
            sql.rollback(conn)

    def drop_table_if_exists(sql, conn, cursor, obj):
        sql._drop_if_exists(conn, cursor, "TABLE", obj)
    def drop_view_if_exists(sql, conn, cursor, obj):
        sql._drop_if_exists(conn, cursor, "VIEW", obj)

    def drop_sequence_if_exists(sql, conn, cursor, key):
        try:
            sql.drop_sequence(conn, cursor, key)
        except sql.module.DatabaseError:
            sql.rollback(conn)

    def drop_column_if_exists(sql, conn, cursor, table, column):
        try:
            sql.ddl(conn, cursor,
                    "ALTER TABLE " + table + " DROP COLUMN " + column)
        except sql.module.DatabaseError:
            sql.rollback(conn)

    def configure_ddl_implicit_commit(sql, conn, cursor):
        if 'create_table_epilogue' not in sql.config:
            sql.config['create_table_epilogue'] = ''
        for val in ['true', 'false']:
            sql.config['ddl_implicit_commit'] = val
            sql._set_flavour()
            if sql._test_ddl(conn, cursor):
                sql.log.info("ddl_implicit_commit=%s", val)
                return
        raise Exception("Can not test for DDL implicit commit.")

    def _test_ddl(sql, conn, cursor):
        """Test whether DDL performs implicit commit."""
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        try:
            sql.ddl(
                conn, cursor,
                "CREATE TABLE abe_test_1 ("
                " abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY,"
                " foo VARCHAR(10))")
            sql.rollback(conn)
            sql.selectall(cursor, "SELECT MAX(abe_test_1_id) FROM abe_test_1")
            return True
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            return False
        except Exception:
            sql.rollback(conn)
            return False
        finally:
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")

    def configure_create_table_epilogue(sql, conn, cursor):
        for val in ['', ' ENGINE=InnoDB']:
            sql.config['create_table_epilogue'] = val
            sql._set_flavour()
            if sql._test_transaction(conn, cursor):
                sql.log.info("create_table_epilogue='%s'", val)
                return
        raise Exception("Can not create a transactional table.")

    def _test_transaction(sql, conn, cursor):
        """Test whether CREATE TABLE needs ENGINE=InnoDB for rollback."""
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        try:
            sql.ddl(
                conn, cursor,
                "CREATE TABLE abe_test_1 (a NUMERIC(12))")
            sql.sql(cursor, "INSERT INTO abe_test_1 (a) VALUES (4)")
            sql.commit(conn)
            sql.sql(cursor, "INSERT INTO abe_test_1 (a) VALUES (5)")
            sql.rollback(conn)
            data = [int(row[0]) for row in sql.selectall(
                    cursor, "SELECT a FROM abe_test_1")]
            return data == [4]
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            return False
        except Exception, e:
            sql.rollback(conn)
            return False
        finally:
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")

    def configure_max_varchar(sql, conn, cursor):
        """Find the maximum VARCHAR width, up to 0xffffffff"""
        lo = 0
        hi = 1 << 32
        mid = hi - 1
        sql.config['max_varchar'] = str(mid)
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        while True:
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")
            try:
                sql.ddl(conn, cursor,
                        """CREATE TABLE abe_test_1
                           (a VARCHAR(%d), b VARCHAR(%d))""" % (mid, mid))
                sql.sql(cursor,
                        "INSERT INTO abe_test_1 (a, b) VALUES ('x', 'y')")
                row = sql.selectrow(cursor, "SELECT a, b FROM abe_test_1")
                if [x for x in row] == ['x', 'y']:
                    lo = mid
                else:
                    hi = mid
            except sql.module.DatabaseError, e:
                sql.rollback(conn)
                hi = mid
            except Exception, e:
                sql.rollback(conn)
                hi = mid
            if lo + 1 == hi:
                sql.config['max_varchar'] = str(lo)
                sql.log.info("max_varchar=%s", sql.config['max_varchar'])
                break
            mid = (lo + hi) / 2
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")

    def configure_max_precision(sql, conn, cursor):
        sql.config['max_precision'] = None  # XXX

    def configure_clob_type(sql, conn, cursor):
        """Find the name of the CLOB type, if any."""
        long_str = 'x' * 10000
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        for val in ['CLOB', 'LONGTEXT', 'TEXT', 'LONG']:
            try:
                sql.ddl(conn, cursor, "CREATE TABLE abe_test_1 (a %s)" % (val,))
                sql.sql(cursor, "INSERT INTO abe_test_1 (a) VALUES (?)",
                        (sql.binin(long_str),))
                out = sql.selectrow(cursor, "SELECT a FROM abe_test_1")[0]
                if sql.binout(out) == long_str:
                    sql.config['clob_type'] = val
                    sql.log.info("clob_type=%s", val)
                    return
                else:
                    sql.log.debug("out=%s", repr(out))
            except sql.module.DatabaseError, e:
                sql.rollback(conn)
            except Exception, e:
                try:
                    sql.rollback(conn)
                except:
                    # Fetching a CLOB really messes up Easysoft ODBC Oracle.
                    #store.reconnect()
                    raise
            finally:
                sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        sql.log.info("No native type found for CLOB.")
        sql.config['clob_type'] = NO_CLOB

    def _test_binary_type(sql, conn, cursor):
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        try:
            # XXX The 10000 should be configurable: max_desired_binary?
            sql.ddl(conn, cursor, """
                CREATE TABLE abe_test_1 (
                    test_id NUMERIC(2) NOT NULL PRIMARY KEY,
                    test_bit BINARY(32),
                    test_varbit VARBINARY(10000))""")
            val = str(''.join(map(chr, range(0, 256, 8))))
            sql.sql(cursor,
                    "INSERT INTO abe_test_1 (test_id, test_bit, test_varbit)"
                    " VALUES (?, ?, ?)",
                    (1, sql.revin(val), sql.binin(val)))
            (bit, vbit) = sql.selectrow(
                cursor, "SELECT test_bit, test_varbit FROM abe_test_1")
            if sql.revout(bit) != val:
                return False
            if sql.binout(vbit) != val:
                return False
            return True
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            return False
        except Exception, e:
            sql.rollback(conn)
            return False
        finally:
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")

    def _test_int_type(sql, conn, cursor):
        sql.drop_view_if_exists(conn, cursor, "abe_test_v1")
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        try:
            sql.ddl(conn, cursor, """
                CREATE TABLE abe_test_1 (
                    test_id NUMERIC(2) NOT NULL PRIMARY KEY,
                    txout_value NUMERIC(30), i2 NUMERIC(20))""")
            # XXX No longer needed?
            sql.ddl(conn, cursor, """
                CREATE VIEW abe_test_v1 AS
                SELECT test_id,
                       CAST(txout_value AS DECIMAL(50)) txout_approx_value,
                       txout_value i1,
                       i2
                  FROM abe_test_1""")
            v1 = 2099999999999999
            v2 = 1234567890
            sql.sql(cursor, "INSERT INTO abe_test_1 (test_id, txout_value, i2)"
                    " VALUES (?, ?, ?)",
                    (1, sql.intin(v1), v2))
            sql.commit(conn)
            prod, o1 = sql.selectrow(
                cursor, "SELECT txout_approx_value * i2, i1 FROM abe_test_v1")
            prod = int(prod)
            o1 = int(o1)
            if prod < v1 * v2 * 1.0001 and prod > v1 * v2 * 0.9999 and o1 == v1:
                return True
            return False
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            return False
        except Exception, e:
            sql.rollback(conn)
            return False
        finally:
            sql.drop_view_if_exists(conn, cursor, "abe_test_v1")
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")

    def _test_sequence_type(sql, conn, cursor):
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        sql.drop_sequence_if_exists(conn, cursor, "abe_test_1")

        try:
            sql.ddl(conn, cursor, """
                CREATE TABLE abe_test_1 (
                    abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY,
                    foo VARCHAR(10)
                )""")
            sql.create_sequence(conn, cursor, 'abe_test_1')
            id1 = sql.new_id(cursor, 'abe_test_1')
            id2 = sql.new_id(cursor, 'abe_test_1')
            if int(id1) != int(id2):
                return True
            return False
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            return False
        except Exception, e:
            sql.rollback(conn)
            return False
        finally:
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")
            try:
                sql.drop_sequence(conn, cursor, "abe_test_1")
            except sql.module.DatabaseError:
                sql.rollback(conn)

    def configure_limit_style(sql, conn, cursor):
        for val in ['native', 'emulated']:
            sql.config['limit_style'] = val
            sql._set_flavour()
            if sql._test_limit_style(conn, cursor):
                sql.log.info("limit_style=%s", val)
                return
        raise Exception("Can not emulate LIMIT.")

    def _test_limit_style(sql, conn, cursor):
        sql.drop_table_if_exists(conn, cursor, "abe_test_1")
        try:
            sql.ddl(conn, cursor, """
                CREATE TABLE abe_test_1 (
                    abe_test_1_id NUMERIC(12) NOT NULL PRIMARY KEY
                )""")
            for id in (2, 4, 6, 8):
                sql.sql(cursor,
                        "INSERT INTO abe_test_1 (abe_test_1_id) VALUES (?)",
                        (id,))
            rows = sql.selectall(cursor, """
                SELECT abe_test_1_id FROM abe_test_1 ORDER BY abe_test_1_id
                 LIMIT 3""")
            return [int(row[0]) for row in rows] == [2, 4, 6]
        except sql.module.DatabaseError, e:
            sql.rollback(conn)
            return False
        except Exception, e:
            sql.rollback(conn)
            return False
        finally:
            sql.drop_table_if_exists(conn, cursor, "abe_test_1")

# XXX testing
if __name__ == '__main__':
    import sys, psycopg2, sqlite3
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(message)s")
    #sql = SqlAbstraction(psycopg2, {'binary_type': 'pg-bytea'})
    #conn = psycopg2.connect(database="abe")
    sql = SqlAbstraction(sqlite3, {})
    conn = sqlite3.connect('tmp.sqlite')
    print sql.configure(conn, conn.cursor())
