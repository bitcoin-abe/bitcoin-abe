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

NO_CLOB = 'BUG_NO_CLOB'
STMT_RE = re.compile(r"([^']+)((?:'[^']*')?)")

class SqlAbstraction(object):

    """
    Database abstraction class based on DB-API 2 and standard SQL with
    workarounds to support SQLite3, PostgreSQL/psycopg2, MySQL,
    Oracle, ODBC, and IBM DB2.
    """

    def __init__(sql, args):
        sql.module = args.module
        sql.connect_args = args.connect_args
        sql.prefix = args.prefix
        sql.config = args.config

        sql.log    = logging.getLogger(__name__)
        sql.sqllog = logging.getLogger(__name__ + ".sql")
        if not args.log_sql:
            sql.sqllog.setLevel(logging.WARNING)

        sql._conn = None
        sql._cursor = None
        sql.auto_reconnect = False
        sql.in_transaction = False
        sql._set_flavour()

    def _set_flavour(sql):
        def identity(x):
            return x
        transform = identity
        transform_stmt = sql._transform_stmt
        selectall = sql._selectall

        if sql.module.paramstyle in ('format', 'pyformat'):
            transform_stmt = sql._qmark_to_format(transform_stmt)
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
            return None if x is None else x[::-1]
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
            # Work around sqlite3's integer overflow.
            transform = sql._approximate(transform)

        else:
            raise Exception("Unsupported int-type %s" % (val,))

        val = sql.config.get('sequence_type')
        if val in (None, 'update'):
            new_id = lambda key: sql._new_id_update(key)
            create_sequence = lambda key: sql._create_sequence_update(key)
            drop_sequence = lambda key: sql._drop_sequence_update(key)

        elif val == 'mysql':
            new_id = lambda key: sql._new_id_mysql(key)
            create_sequence = lambda key: sql._create_sequence_mysql(key)
            drop_sequence = lambda key: sql._drop_sequence_mysql(key)

        else:
            create_sequence = lambda key: sql._create_sequence(key)
            drop_sequence = lambda key: sql._drop_sequence(key)

            if val == 'oracle':
                new_id = lambda key: sql._new_id_oracle(key)
            elif val == 'nvf':
                new_id = lambda key: sql._new_id_nvf(key)
            elif val == 'postgres':
                new_id = lambda key: sql._new_id_postgres(key)
            elif val == 'db2':
                new_id = lambda key: sql._new_id_db2(key)
                create_sequence = lambda key: sql._create_sequence_db2(key)
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

    def connect(sql):
        cargs = sql.connect_args

        if cargs is None:
            conn = sql.module.connect()
        else:
            try:
                conn = sql._connect(cargs)
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
                conn = sql._connect(to_utf8(cargs))
                sql.log.info("Connection required conversion to UTF-8")

        return conn

    def _connect(sql, cargs):
        if isinstance(cargs, dict):
            if ""  in cargs:
                cargs = cargs.copy()
                nkwargs = cargs[""]
                del(cargs[""])
                if isinstance(nkwargs, list):
                    return sql.module.connect(*nkwargs, **cargs)
                return sql.module.connect(nkwargs, **cargs)
            else:
                return sql.module.connect(**cargs)
        if isinstance(cargs, list):
            return sql.module.connect(*cargs)
        return sql.module.connect(cargs)

    def conn(sql):
        if sql._conn is None:
            sql._conn = sql.connect()
        return sql._conn

    def cursor(sql):
        if sql._cursor is None:
            sql._cursor = sql.conn().cursor()
        return sql._cursor

    def rowcount(sql):
        return sql.cursor().rowcount

    def reconnect(sql):
        sql.log.info("Reconnecting to database.")
        try:
            sql.close()
        except Exception:
            pass
        return sql.conn()

    # Run transform_chunk on each chunk between string literals.
    def _transform_stmt(sql, stmt):
        def transform_chunk(match):
            return sql.transform_chunk(match.group(1)) + match.group(2)
        return STMT_RE.sub(transform_chunk, stmt)

    # Convert standard placeholders to Python "format" style.
    def _qmark_to_format(sql, fn):
        def ret(stmt):
            return fn(stmt.replace('%', '%%').replace("?", "%s"))
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
        if sql.config.get('max_precision', "") == "":
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

    def _approximate(store, fn):
        def repl(match):
            return 'CAST(' + match.group(1) + match.group(2) + ' AS DOUBLE PRECISION) ' \
                + match.group(1) + '_approx' + match.group(2)
        def ret(stmt):
            return fn(re.sub(r'\b(\w+)(\w*) \1_approx\2\b', repl, stmt))
        return ret

    def emulate_limit(sql, selectall):
        limit_re = re.compile(r"(.*)\bLIMIT\s+(\?|\d+)\s*\Z", re.DOTALL)
        def ret(stmt, params=()):
            match = limit_re.match(sql.transform_stmt_cached(stmt))
            if match:
                if match.group(2) == '?':
                    n = params[-1]
                    params = params[:-1]
                else:
                    n = int(match.group(2))
                sql.cursor().execute(match.group(1), params)
                return [ sql.cursor().fetchone() for i in xrange(n) ]
            return selectall(stmt, params)
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

    def _execute(sql, stmt, params):
        try:
            sql.cursor().execute(stmt, params)
        except (sql.module.OperationalError, sql.module.InternalError, sql.module.ProgrammingError) as e:
            if sql.in_transaction or not sql.auto_reconnect:
                raise

            sql.log.warning("Replacing possible stale cursor: %s", e)

            try:
                sql.reconnect()
            except Exception:
                sql.log.exception("Failed to reconnect")
                raise e

            sql.cursor().execute(stmt, params)

    def sql(sql, stmt, params=()):
        cached = sql.transform_stmt_cached(stmt)
        sql.sqllog.info("EXEC: %s %r", cached, params)
        try:
            sql._execute(cached, params)
        except Exception as e:
            sql.sqllog.info("EXCEPTION: %s", e)
            raise
        finally:
            sql.in_transaction = True

    def ddl(sql, stmt):
        stmt = sql.transform_stmt(stmt)
        sql.sqllog.info("DDL: %s", stmt)
        try:
            sql.cursor().execute(stmt)
        except Exception as e:
            sql.sqllog.info("EXCEPTION: %s", e)
            raise
        if sql.config.get('ddl_implicit_commit') == 'false':
            sql.commit()
        else:
            sql.in_transaction = False

    def selectrow(sql, stmt, params=()):
        sql.sql(stmt, params)
        ret = sql.cursor().fetchone()
        sql.sqllog.debug("FETCH: %s", ret)
        return ret

    def _selectall(sql, stmt, params=()):
        sql.sql(stmt, params)
        ret = sql.cursor().fetchall()
        sql.sqllog.debug("FETCHALL: %s", ret)
        return ret

    def _new_id_update(sql, key):
        """
        Allocate a synthetic identifier by updating a table.
        """
        while True:
            row = sql.selectrow("SELECT nextid FROM %ssequences WHERE sequence_key = ?" % (sql.prefix), (key,))
            if row is None:
                raise Exception("Sequence %s does not exist" % key)

            ret = row[0]
            sql.sql("UPDATE %ssequences SET nextid = nextid + 1"
                    " WHERE sequence_key = ? AND nextid = ?" % sql.prefix,
                    (key, ret))
            if sql.cursor().rowcount == 1:
                return ret
            sql.log.info('Contention on %ssequences %s:%d' % sql.prefix, key, ret)

    def _get_sequence_initial_value(sql, key):
        (ret,) = sql.selectrow("SELECT MAX(" + key + "_id) FROM " + key)
        ret = 1 if ret is None else ret + 1
        return ret

    def _create_sequence_update(sql, key):
        sql.commit()
        ret = sql._get_sequence_initial_value(key)
        try:
            sql.sql("INSERT INTO %ssequences (sequence_key, nextid)"
                    " VALUES (?, ?)" % sql.prefix, (key, ret))
        except sql.module.DatabaseError as e:
            sql.rollback()
            try:
                sql.ddl("""CREATE TABLE %ssequences (
                    sequence_key VARCHAR(100) NOT NULL PRIMARY KEY,
                    nextid NUMERIC(30)
                )""" % sql.prefix)
            except Exception:
                sql.rollback()
                raise e
            sql.sql("INSERT INTO %ssequences (sequence_key, nextid)"
                    " VALUES (?, ?)" % sql.prefix, (key, ret))

    def _drop_sequence_update(sql, key):
        sql.commit()
        sql.sql("DELETE FROM %ssequences WHERE sequence_key = ?" % sql.prefix,
                (key,))
        sql.commit()

    def _new_id_oracle(sql, key):
        (ret,) = sql.selectrow("SELECT " + key + "_seq.NEXTVAL FROM DUAL")
        return ret

    def _create_sequence(sql, key):
        sql.ddl("CREATE SEQUENCE %s_seq START WITH %d"
                % (key, sql._get_sequence_initial_value(key)))

    def _drop_sequence(sql, key):
        sql.ddl("DROP SEQUENCE %s_seq" % (key,))

    def _new_id_nvf(sql, key):
        (ret,) = sql.selectrow("SELECT NEXT VALUE FOR " + key + "_seq")
        return ret

    def _new_id_postgres(sql, key):
        (ret,) = sql.selectrow("SELECT NEXTVAL('" + key + "_seq')")
        return ret

    def _create_sequence_db2(sql, key):
        sql.commit()
        try:
            rows = sql.selectall("SELECT 1 FROM %sdual" % sql.prefix)
            if len(rows) != 1:
                sql.sql("INSERT INTO %sdual(x) VALUES ('X')" % sql.prefix)
        except sql.module.DatabaseError as e:
            sql.rollback()
            sql.drop_table_if_exists('%sdual' % sql.prefix)
            sql.ddl("CREATE TABLE %sdual (x CHAR(1))" % sql.prefix)
            sql.sql("INSERT INTO %sdual(x) VALUES ('X')" % sql.prefix)
            sql.log.info("Created silly table %sdual" % sql.prefix)
        sql._create_sequence(key)

    def _new_id_db2(sql, key):
        (ret,) = sql.selectrow("SELECT NEXTVAL FOR " + key + "_seq"
                               " FROM %sdual" % sql.prefix)
        return ret

    def _create_sequence_mysql(sql, key):
        sql.ddl("CREATE TABLE %s_seq (id BIGINT AUTO_INCREMENT PRIMARY KEY)"
                " AUTO_INCREMENT=%d"
                % (key, sql._get_sequence_initial_value(key)))

    def _drop_sequence_mysql(sql, key):
        sql.ddl("DROP TABLE %s_seq" % (key,))

    def _new_id_mysql(sql, key):
        sql.sql("INSERT INTO " + key + "_seq () VALUES ()")
        (ret,) = sql.selectrow("SELECT LAST_INSERT_ID()")
        if ret % 1000 == 0:
            sql.sql("DELETE FROM " + key + "_seq WHERE id < ?", (ret,))
        return ret

    def commit(sql):
        sql.sqllog.info("COMMIT")
        sql.conn().commit()
        sql.in_transaction = False

    def rollback(sql):
        if sql.module is None:
            return
        sql.sqllog.info("ROLLBACK")
        try:
            sql.conn().rollback()
            sql.in_transaction = False
        except sql.module.OperationalError as e:
            sql.log.warning("Reconnecting after rollback error: %s", e)
            sql.reconnect()

    def close(sql):
        conn = sql._conn
        if conn is not None:
            sql.sqllog.info("CLOSE")
            conn.close()
            sql._conn = None
            sql._cursor = None

    def configure(sql):
        sql.configure_ddl_implicit_commit()
        sql.configure_create_table_epilogue()
        sql.configure_max_varchar()
        sql.configure_max_precision()
        sql.configure_clob_type()
        sql.configure_binary_type()
        sql.configure_int_type()
        sql.configure_sequence_type()
        sql.configure_limit_style()

        return sql.config

    def configure_binary_type(sql):
        defaults = ['binary', 'bytearray', 'buffer', 'hex', 'pg-bytea']
        tests = (defaults
                 if sql.config.get('binary_type') is None else
                 [ sql.config['binary_type'] ])

        for val in tests:
            sql.config['binary_type'] = val
            sql._set_flavour()
            if sql._test_binary_type():
                sql.log.info("binary_type=%s", val)
                return

        raise Exception(
            "No known binary data representation works"
            if len(tests) > 1 else
            "Binary type " + tests[0] + " fails test")

    def configure_int_type(sql):
        defaults = ['int', 'decimal', 'str']
        tests = (defaults if sql.config.get('int_type') is None else
                 [ sql.config['int_type'] ])

        for val in tests:
            sql.config['int_type'] = val
            sql._set_flavour()
            if sql._test_int_type():
                sql.log.info("int_type=%s", val)
                return
        raise Exception(
            "No known large integer representation works"
            if len(tests) > 1 else
            "Integer type " + tests[0] + " fails test")

    def configure_sequence_type(sql):
        for val in ['nvf', 'oracle', 'postgres', 'mysql', 'db2', 'update']:
            sql.config['sequence_type'] = val
            sql._set_flavour()
            if sql._test_sequence_type():
                sql.log.info("sequence_type=%s", val)
                return
        raise Exception("No known sequence type works")

    def _drop_if_exists(sql, otype, name):
        try:
            sql.sql("DROP " + otype + " " + name)
            sql.commit()
        except sql.module.DatabaseError:
            sql.rollback()

    def drop_table_if_exists(sql, obj):
        sql._drop_if_exists("TABLE", obj)
    def drop_view_if_exists(sql, obj):
        sql._drop_if_exists("VIEW", obj)

    def drop_sequence_if_exists(sql, key):
        try:
            sql.drop_sequence(key)
        except sql.module.DatabaseError:
            sql.rollback()

    def drop_column_if_exists(sql, table, column):
        try:
            sql.ddl("ALTER TABLE " + table + " DROP COLUMN " + column)
        except sql.module.DatabaseError:
            sql.rollback()

    def configure_ddl_implicit_commit(sql):
        if 'create_table_epilogue' not in sql.config:
            sql.config['create_table_epilogue'] = ''
        for val in ['true', 'false']:
            sql.config['ddl_implicit_commit'] = val
            sql._set_flavour()
            if sql._test_ddl():
                sql.log.info("ddl_implicit_commit=%s", val)
                return
        raise Exception("Can not test for DDL implicit commit.")

    def _test_ddl(sql):
        """Test whether DDL performs implicit commit."""
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        try:
            sql.ddl(
                "CREATE TABLE %stest_1 ("
                " %stest_1_id NUMERIC(12) NOT NULL PRIMARY KEY,"
                " foo VARCHAR(10))" % (sql.prefix, sql.prefix))
            sql.rollback()
            sql.selectall("SELECT MAX(%stest_1_id) FROM %stest_1"
                          % (sql.prefix, sql.prefix))
            return True
        except sql.module.DatabaseError as e:
            sql.rollback()
            return False
        except Exception:
            sql.rollback()
            return False
        finally:
            sql.drop_table_if_exists("%stest_1" % sql.prefix)

    def configure_create_table_epilogue(sql):
        for val in ['', ' ENGINE=InnoDB']:
            sql.config['create_table_epilogue'] = val
            sql._set_flavour()
            if sql._test_transaction():
                sql.log.info("create_table_epilogue='%s'", val)
                return
        raise Exception("Can not create a transactional table.")

    def _test_transaction(sql):
        """Test whether CREATE TABLE needs ENGINE=InnoDB for rollback."""
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        try:
            sql.ddl("CREATE TABLE %stest_1 (a NUMERIC(12))" % sql.prefix)
            sql.sql("INSERT INTO %stest_1 (a) VALUES (4)" % sql.prefix)
            sql.commit()
            sql.sql("INSERT INTO %stest_1 (a) VALUES (5)" % sql.prefix)
            sql.rollback()
            data = [int(row[0]) for row in sql.selectall(
                    "SELECT a FROM %stest_1" % sql.prefix)]
            return data == [4]
        except sql.module.DatabaseError as e:
            sql.rollback()
            return False
        except Exception as e:
            sql.rollback()
            return False
        finally:
            sql.drop_table_if_exists("%stest_1" % sql.prefix)

    def configure_max_varchar(sql):
        """Find the maximum VARCHAR width, up to 0xffffffff"""
        lo = 0
        hi = 1 << 32
        mid = hi - 1
        sql.config['max_varchar'] = str(mid)
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        while True:
            sql.drop_table_if_exists("%stest_1" % sql.prefix)
            try:
                sql.ddl("""CREATE TABLE %stest_1
                           (a VARCHAR(%d), b VARCHAR(%d))"""
                        % (sql.prefix, mid, mid))
                sql.sql("INSERT INTO %stest_1 (a, b) VALUES ('x', 'y')"
                        % sql.prefix)
                row = sql.selectrow("SELECT a, b FROM %stest_1"
                                    % sql.prefix)
                if [x for x in row] == ['x', 'y']:
                    lo = mid
                else:
                    hi = mid
            except sql.module.DatabaseError as e:
                sql.rollback()
                hi = mid
            except Exception as e:
                sql.rollback()
                hi = mid
            if lo + 1 == hi:
                sql.config['max_varchar'] = str(lo)
                sql.log.info("max_varchar=%s", sql.config['max_varchar'])
                break
            mid = (lo + hi) / 2
        sql.drop_table_if_exists("%stest_1" % sql.prefix)

    def configure_max_precision(sql):
        sql.config['max_precision'] = ""  # XXX

    def configure_clob_type(sql):
        """Find the name of the CLOB type, if any."""
        long_str = 'x' * 10000
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        for val in ['CLOB', 'LONGTEXT', 'TEXT', 'LONG']:
            try:
                sql.ddl("CREATE TABLE %stest_1 (a %s)" % (sql.prefix, val))
                sql.sql("INSERT INTO %stest_1 (a) VALUES (?)", (sql.prefix, sql.binin(long_str)))
                out = sql.selectrow("SELECT a FROM %stest_1" % sql.prefix)[0]
                if sql.binout(out) == long_str:
                    sql.config['clob_type'] = val
                    sql.log.info("clob_type=%s", val)
                    return
                else:
                    sql.log.debug("out=%s", repr(out))
            except sql.module.DatabaseError as e:
                sql.rollback()
            except Exception as e:
                try:
                    sql.rollback()
                except Exception:
                    # Fetching a CLOB really messes up Easysoft ODBC Oracle.
                    sql.reconnect()
                    raise
            finally:
                sql.drop_table_if_exists("%stest_1" % sql.prefix)
        sql.log.info("No native type found for CLOB.")
        sql.config['clob_type'] = NO_CLOB

    def _test_binary_type(sql):
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        try:
            # XXX The 10000 should be configurable: max_desired_binary?
            sql.ddl("""
                CREATE TABLE %stest_1 (
                    test_id NUMERIC(2) NOT NULL PRIMARY KEY,
                    test_bit BINARY(32),
                    test_varbit VARBINARY(10000))""" % sql.prefix)
            val = str(''.join(map(chr, range(0, 256, 8))))
            sql.sql("INSERT INTO %stest_1 (test_id, test_bit, test_varbit)"
                    " VALUES (?, ?, ?)" % sql.prefix,
                    (1, sql.revin(val), sql.binin(val)))
            (bit, vbit) = sql.selectrow("SELECT test_bit, test_varbit FROM %stest_1" % sql.prefix)
            if sql.revout(bit) != val:
                return False
            if sql.binout(vbit) != val:
                return False
            return True
        except sql.module.DatabaseError as e:
            sql.rollback()
            return False
        except Exception as e:
            sql.rollback()
            return False
        finally:
            sql.drop_table_if_exists("%stest_1" % sql.prefix)

    def _test_int_type(sql):
        sql.drop_view_if_exists("%stest_v1" % sql.prefix)
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        try:
            sql.ddl("""
                CREATE TABLE %stest_1 (
                    test_id NUMERIC(2) NOT NULL PRIMARY KEY,
                    i1 NUMERIC(30), i2 NUMERIC(20))""" % sql.prefix)
            # XXX No longer needed?
            sql.ddl("""
                CREATE VIEW %stest_v1 AS
                SELECT test_id,
                       i1 i1_approx,
                       i1,
                       i2
                  FROM %stest_1""" % (sql.prefix, sql.prefix))
            v1 = 2099999999999999
            v2 = 1234567890
            sql.sql("INSERT INTO %stest_1 (test_id, i1, i2)"
                    " VALUES (?, ?, ?)" % sql.prefix,
                    (1, sql.intin(v1), v2))
            sql.commit()
            prod, o1 = sql.selectrow("SELECT i1_approx * i2, i1 FROM %stest_v1" % sql.prefix)
            prod = int(prod)
            o1 = int(o1)
            if prod < v1 * v2 * 1.0001 and prod > v1 * v2 * 0.9999 and o1 == v1:
                return True
            return False
        except sql.module.DatabaseError as e:
            sql.rollback()
            return False
        except Exception as e:
            sql.rollback()
            return False
        finally:
            sql.drop_view_if_exists("%stest_v1" % sql.prefix)
            sql.drop_table_if_exists("%stest_1" % sql.prefix)

    def _test_sequence_type(sql):
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        sql.drop_sequence_if_exists("%stest_1" % sql.prefix)

        try:
            sql.ddl("""
                CREATE TABLE %stest_1 (
                    %stest_1_id NUMERIC(12) NOT NULL PRIMARY KEY,
                    foo VARCHAR(10)
                )""" % (sql.prefix, sql.prefix))
            sql.create_sequence('%stest_1' % sql.prefix)
            id1 = sql.new_id('%stest_1' % sql.prefix)
            id2 = sql.new_id('%stest_1' % sql.prefix)
            if int(id1) != int(id2):
                return True
            return False
        except sql.module.DatabaseError as e:
            sql.rollback()
            return False
        except Exception as e:
            sql.rollback()
            return False
        finally:
            sql.drop_table_if_exists("%stest_1" % sql.prefix)
            try:
                sql.drop_sequence("%stest_1" % sql.prefix)
            except sql.module.DatabaseError:
                sql.rollback()

    def configure_limit_style(sql):
        for val in ['native', 'emulated']:
            sql.config['limit_style'] = val
            sql._set_flavour()
            if sql._test_limit_style():
                sql.log.info("limit_style=%s", val)
                return
        raise Exception("Can not emulate LIMIT.")

    def _test_limit_style(sql):
        sql.drop_table_if_exists("%stest_1" % sql.prefix)
        try:
            sql.ddl("""
                CREATE TABLE %stest_1 (
                    %stest_1_id NUMERIC(12) NOT NULL PRIMARY KEY
                )""" % (sql.prefix, sql.prefix))
            for id in (2, 4, 6, 8):
                sql.sql("INSERT INTO %stest_1 (%stest_1_id) VALUES (?)"
                        % (sql.prefix, sql.prefix),
                        (id,))
            rows = sql.selectall("""
                SELECT %stest_1_id FROM %stest_1 ORDER BY %stest_1_id
                 LIMIT 3""" % (sql.prefix, sql.prefix, sql.prefix))
            return [int(row[0]) for row in rows] == [2, 4, 6]
        except sql.module.DatabaseError as e:
            sql.rollback()
            return False
        except Exception as e:
            sql.rollback()
            return False
        finally:
            sql.drop_table_if_exists("%stest_1" % sql.prefix)
