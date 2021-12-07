# Copyright(C) 2011,2012,2013 by John Tobey <jtobey@john-edwin-tobey.org>

"""sql_abstraction.py: feature-detecting, SQL-transforming database abstraction layer"""

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
import decimal
import logging
from typing import Union
from .util import b2hex, hex2b
from .constants import MAX_SCRIPT, NO_CLOB

STMT_RE = re.compile(r"([^']+)((?:'[^']*')?)")


class SqlAbstraction:

    """
    Database abstraction class based on DB-API 2 and standard SQL with
    workarounds to support SQLite3, PostgreSQL/psycopg2, MySQL,
    Oracle, ODBC, and IBM DB2.
    """

    def __init__(self, args):
        self.module = args.module
        self.connect_args = args.connect_args
        self.prefix = args.prefix
        self.config = args.config
        self.binary_type = args.binary_type
        self.int_type = args.int_type

        self.log = logging.getLogger(__name__)
        self.sqllog = logging.getLogger(__name__ + ".sql")
        if not args.log_sql:
            self.sqllog.setLevel(logging.WARNING)

        self._conn = None
        self._cursor = None
        self.auto_reconnect = False
        self.in_transaction = False
        self._set_flavour()

    def _set_flavour(self):
        # pylint: disable=unnecessary-lambda
        def identity(
            val: Union[str, bytes, bytearray, memoryview]
        ) -> Union[str, bytes, bytearray, memoryview]:
            return val

        transform = identity
        transform_stmt = self._transform_stmt
        selectall = self._selectall

        if self.module.paramstyle in ("format", "pyformat"):
            transform_stmt = self._qmark_to_format(transform_stmt)
        elif self.module.paramstyle == "named":
            transform_stmt = self._qmark_to_named(transform_stmt)
        elif self.module.paramstyle != "qmark":
            self.log.warning(
                "Database parameter style is " "%s, trying qmark",
                self.module.paramstyle,
            )

        # Binary I/O with the database.
        # Reversed versions exist for Bitcoin hashes; since the
        # protocol treats them as 256-bit integers and represents them
        # as little endian, we have to reverse them in hex to satisfy
        # human expectations.
        def rev(
            val: Union[str, bytes, bytearray, memoryview]
        ) -> Union[None, bytes, bytearray, memoryview]:
            if isinstance(val, str):
                val = bytes(val, "utf-8")
            return None if val is None else val[::-1]

        def to_hex(val: str) -> Union[None, bytes]:
            return None if val is None else hex2b(val)

        def from_hex(val: Union[bytes, bytearray, memoryview]) -> Union[None, str]:
            return None if val is None else b2hex(val)

        def to_hex_rev(val: str) -> Union[None, bytes]:
            return None if val is None else hex2b(val)[::-1]

        def from_hex_rev(val: Union[bytes, bytearray, memoryview]) -> Union[None, str]:
            return None if val is None else b2hex(val[::-1])

        val = self.config.get("binary_type")

        if val in (None, "str", "binary"):
            binin = identity
            binin_hex = from_hex
            binout = identity
            binout_hex = to_hex
            revin = rev
            revin_hex = from_hex
            revout = rev
            revout_hex = to_hex

        elif val in ("buffer", "bytearray", "pg-bytea"):

            def to_str(val: Union[bytes, bytearray, memoryview]) -> str:
                return str(val, "utf-8")

            if val == "bytearray":

                def to_btype(
                    val: Union[str, bytes, memoryview]
                ) -> Union[None, bytearray]:
                    if isinstance(val, str):
                        val = hex2b(val)
                    return None if val is None else bytearray(val)

            elif val == "buffer":

                def to_btype(val: Union[bytes, bytearray]) -> memoryview:  # type:ignore
                    return None if val is None else memoryview(val)

            else:
                # PostgreSQL can take binary inputs as '\x[<hexadecimal str>]'
                # https://www.postgresql.org/docs/14/datatype-binary.html
                def to_btype(val: Union[str, bytes, bytearray]) -> str:  # type:ignore
                    if isinstance(val, str):
                        val = bytes(val, "utf-8")
                    val = b2hex(val)
                    return "\\x" + val

                def pg_to_str(val: Union[bytes, bytearray, memoryview]) -> str:
                    # psycopg2 returns database objects as memory addresses
                    # XXX This is a really ugly fix need to force bytes as the data structure throughout.
                    val = bytes(val)
                    try:
                        return str(val, "utf-8")
                    except UnicodeDecodeError:
                        pass
                    try:
                        return "".join(map(chr, val))
                    except UnicodeDecodeError as error:
                        raise error

            binin = to_btype
            binin_hex = to_btype
            binout = to_str
            binout_hex = to_hex
            revin = lambda val: to_btype(rev(val))
            revin_hex = to_btype
            revout = rev
            revout_hex = to_hex

            if val == "pg-bytea":
                transform_stmt = self._binary_as_bytea(transform_stmt)
                binout = pg_to_str
                binout_hex = lambda val: bytes(val)
                revout = lambda val: pg_to_str(rev(val))
                revout_hex = lambda val: rev(bytes(val))

        elif val == "hex":
            transform = self._binary_as_hex(transform)
            binin = to_hex
            binin_hex = identity
            binout = from_hex
            binout_hex = identity
            revin = to_hex_rev
            revin_hex = identity
            revout = from_hex_rev
            revout_hex = identity

        else:
            raise Exception(f"Unsupported binary-type {val}")

        val = self.config.get("int_type")
        if val in (None, "int"):
            intin = identity

        elif val == "decimal":

            def _intin(val):
                return None if val is None else decimal.Decimal(val)

            intin = _intin

        elif val == "str":

            def _intin(val):
                return None if val is None else str(val)

            intin = _intin
            # Work around sqlite3's integer overflow.
            transform = self._approximate(transform)

        else:
            raise Exception(f"Unsupported int-type {val}")

        val = self.config.get("sequence_type")
        if val in (None, "update"):
            new_id = lambda key: self._new_id_update(key)
            create_sequence = lambda key: self._create_sequence_update(key)
            drop_sequence = lambda key: self._drop_sequence_update(key)

        elif val == "mysql":
            new_id = lambda key: self._new_id_mysql(key)
            create_sequence = lambda key: self._create_sequence_mysql(key)
            drop_sequence = lambda key: self._drop_sequence_mysql(key)

        else:
            create_sequence = lambda key: self._create_sequence(key)
            drop_sequence = lambda key: self._drop_sequence(key)

            if val == "oracle":
                new_id = lambda key: self._new_id_oracle(key)
            elif val == "nvf":
                new_id = lambda key: self._new_id_nvf(key)
            elif val == "postgres":
                new_id = lambda key: self._new_id_postgres(key)
            elif val == "db2":
                new_id = lambda key: self._new_id_db2(key)
                create_sequence = lambda key: self._create_sequence_db2(key)
            else:
                raise Exception(f"Unsupported sequence-type {val}")

        # Convert Oracle LOB to str.
        if hasattr(self.module, "LOB") and isinstance(self.module.LOB, type):

            def fix_lob(func):
                def ret(val):
                    return None if val is None else func(str(val))

                return ret

            binout = fix_lob(binout)
            binout_hex = fix_lob(binout_hex)

        val = self.config.get("limit_style")
        if val in (None, "native"):
            pass
        elif val == "emulated":
            selectall = self.emulate_limit(selectall)

        val = self.config.get("concat_style")
        if val in (None, "ansi"):
            pass
        elif val == "mysql":
            transform_stmt = self._transform_concat(transform_stmt)
            # Also squeeze in MySQL VARBINARY length fix
            # Some MySQL version do not auto-convert to BLOB
            transform_stmt = self._transform_varbinary(transform_stmt)

        transform_stmt = self._append_table_epilogue(transform_stmt)

        transform = self._fallback_to_lob(transform)
        transform = self._fallback_to_approximate(transform)

        self.transform_chunk = transform
        self.transform_stmt = transform_stmt
        self.selectall = selectall
        self._cache = {}

        self.binin = binin
        self.binin_hex = binin_hex
        self.binout = binout
        self.binout_hex = binout_hex
        self.revin = revin
        self.revin_hex = revin_hex
        self.revout = revout
        self.revout_hex = revout_hex

        # Might reimplement these someday...
        def binout_int(val):
            if val is None:
                return None
            return int(binout_hex(val), 16)

        def binin_int(val, bits):
            if val is None:
                return None
            return binin_hex(("%%0%dx" % (bits / 4)) % val)

        self.binout_int = binout_int
        self.binin_int = binin_int

        self.intin = intin
        self.new_id = new_id
        self.create_sequence = create_sequence
        self.drop_sequence = drop_sequence

    def connect(self):
        """Connect to the database"""
        cargs = self.connect_args

        if cargs is None:
            conn = self.module.connect()
        else:
            try:
                conn = self._connect(cargs)
            except UnicodeError:
                # Perhaps this driver needs its strings encoded.
                # Python's default is ASCII.  Let's try UTF-8, which
                # should be the default anyway.
                # import locale
                # enc = locale.getlocale()[1] or locale.getdefaultlocale()[1]
                enc = "UTF-8"

                def to_utf8(obj):
                    if isinstance(obj, dict):
                        for k in obj.keys():
                            obj[k] = to_utf8(obj[k])
                    if isinstance(obj, list):
                        return map(to_utf8, obj)
                    if isinstance(obj, str):
                        return obj.encode(enc)
                    return obj

                conn = self._connect(to_utf8(cargs))
                self.log.info("Connection required conversion to UTF-8")

        return conn

    def _connect(self, cargs):
        if isinstance(cargs, dict):
            if "" in cargs:
                cargs = cargs.copy()
                nkwargs = cargs[""]
                del cargs[""]
                if isinstance(nkwargs, list):
                    return self.module.connect(*nkwargs, **cargs)
                return self.module.connect(nkwargs, **cargs)
            else:
                return self.module.connect(**cargs)
        if isinstance(cargs, list):
            return self.module.connect(*cargs)
        return self.module.connect(cargs)

    def conn(self):
        if self._conn is None:
            self._conn = self.connect()
        return self._conn

    def cursor(self):
        if self._cursor is None:
            self._cursor = self.conn().cursor()
        return self._cursor

    def rowcount(self):
        return self.cursor().rowcount

    def reconnect(self):
        self.log.info("Reconnecting to database.")
        try:
            self.close()
        except Exception:
            pass
        return self.conn()

    # Run transform_chunk on each chunk between string literals.
    def _transform_stmt(self, stmt) -> str:
        def transform_chunk(match):
            return self.transform_chunk(match.group(1)) + match.group(2)

        return STMT_RE.sub(transform_chunk, stmt)

    # Convert standard placeholders to Python "format" style.
    def _qmark_to_format(self, func):
        def ret(stmt):
            return func(stmt.replace("%", "%%").replace("?", "%s"))

        return ret

    # Convert standard placeholders to Python "named" style.
    def _qmark_to_named(self, func):
        patt = re.compile(r"\?")

        def ret(stmt):
            i = [0]

            def newname():
                i[0] += 1
                return f":p{i[0]}"

            def transform_chunk(match):
                return patt.sub(newname, match.group(1)) + match.group(2)

            return func(STMT_RE.sub(transform_chunk, stmt))

        return ret

    # Convert the standard BINARY type to a hex string for databases
    # and drivers that don't support BINARY.
    def _binary_as_hex(self, func):
        patt = re.compile(r"\b((?:VAR)?)BINARY\s*\(\s*([0-9]+)\s*\)")
        x_patt = re.compile(r"X\Z")

        def fixup(match) -> str:
            val: str = match.group(1) + f"CHAR({int(match.group(2)) * 2})"
            return val

        def ret(chunk):
            return func(x_patt.sub("", patt.sub(fixup, chunk)))

        return ret

    # Convert the standard BINARY type to the PostgreSQL BYTEA type.
    def _binary_as_bytea(self, func):
        type_patt = re.compile("((?:VAR)?)BINARY\\(([0-9]+)\\)")
        # lit_patt = re.compile("X'((?:[0-9a-fA-F][0-9a-fA-F])*)'")

        def ret(stmt):
            def transform_chunk(match):
                ret = type_patt.sub("BYTEA", match.group(1))
                if match.group(1).endswith("X") and match.group(2) != "":
                    ret = ret[:-1] + "'"
                    for i in str(match.group(2)[1:-1], "utf-8"):
                        ret += r"\\%03o" % ord(i)
                    ret += "'::bytea"
                else:
                    ret += match.group(2)
                return ret

            return func(STMT_RE.sub(transform_chunk, stmt))

        return ret

    # Converts VARCHAR types that are too long to CLOB or similar.
    def _fallback_to_lob(self, func):
        if self.config.get("max_varchar") is None:
            return func
        max_varchar = int(self.config["max_varchar"])

        if self.config.get("clob_type") is None:
            return func
        clob_type = self.config["clob_type"]

        patt = re.compile("VARCHAR\\(([0-9]+)\\)")

        def fixup(match):
            width = int(match.group(1))
            if width > max_varchar and clob_type != NO_CLOB:
                return clob_type
            return match.group()

        def ret(stmt):
            return func(patt.sub(fixup, stmt))

        return ret

    # Convert high-precision NUMERIC and DECIMAL types to DOUBLE PRECISION
    # to avoid integer overflow with SQLite.
    def _fallback_to_approximate(self, func):
        if self.config.get("max_precision", "") == "":
            return func

        max_precision = int(self.config["max_precision"])
        patt = re.compile(r"\b(?:NUMERIC|DECIMAL)\s*\(\s*([0-9]+)\s*(?:,.*?)?\)")

        def fixup(match):
            precision = int(match.group(1))
            if precision > max_precision:
                return "DOUBLE PRECISION"
            return match.group()

        def ret(stmt):
            return func(patt.sub(fixup, stmt))

        return ret

    def _approximate(self, func):
        def repl(match):
            return (
                "CAST("
                + match.group(1)
                + match.group(2)
                + " AS DOUBLE PRECISION) "
                + match.group(1)
                + "_approx"
                + match.group(2)
            )

        def ret(stmt):
            return func(re.sub(r"\b(\w+)(\w*) \1_approx\2\b", repl, stmt))

        return ret

    def emulate_limit(self, selectall):
        limit_re = re.compile(r"(.*)\bLIMIT\s+(\?|\d+)\s*\Z", re.DOTALL)

        def ret(stmt, params=()):
            match = limit_re.match(self.transform_stmt_cached(stmt))
            if match:
                if match.group(2) == "?":
                    num = params[-1]
                    params = params[:-1]
                else:
                    num = int(match.group(2))
                self.cursor().execute(match.group(1), params)
                return [self.cursor().fetchone() for i in range(num)]
            return selectall(stmt, params)

        return ret

    def _transform_concat(self, func):
        concat_re = re.compile(
            r"((?:(?:'[^']*'|\?)\s*\|\|\s*)+(?:'[^']*'|\?))", re.DOTALL
        )

        def repl(match):
            clist = re.sub(r"\s*\|\|\s*", ", ", match.group(1))
            return "CONCAT(" + clist + ")"

        def ret(stmt):
            return func(concat_re.sub(repl, stmt))

        return ret

    def _transform_varbinary(self, func):
        varbinary_re = re.compile(r"VARBINARY\(" + str(MAX_SCRIPT) + r"\)")

        def ret(stmt):
            # Suitable for prefix+length up to 16,777,215 (2^24 - 1)
            return func(varbinary_re.sub("MEDIUMBLOB", stmt))

        return ret

    def _append_table_epilogue(self, func):
        epilogue = self.config.get("create_table_epilogue", "")
        if epilogue == "":
            return func

        patt = re.compile(r"\s*CREATE\s+TABLE\b")

        def ret(stmt):
            if patt.match(stmt):
                stmt += epilogue
            return func(stmt)

        return ret

    def transform_stmt_cached(self, stmt):
        cached = self._cache.get(stmt)
        if cached is None:
            cached = self.transform_stmt(stmt)
            self._cache[stmt] = cached
        return cached

    def _execute(self, stmt, params):
        try:
            self.cursor().execute(stmt, params)
        except (
            self.module.OperationalError,
            self.module.InternalError,
            self.module.ProgrammingError,
        ) as error:
            if self.in_transaction or not self.auto_reconnect:
                raise

            self.log.warning("Replacing possible stale cursor: %s", error)

            try:
                self.reconnect()
            except Exception as error:
                self.log.exception("Failed to reconnect")
                raise error

            self.cursor().execute(stmt, params)

    def sql(self, stmt, params=()):
        cached = self.transform_stmt_cached(stmt)
        self.sqllog.info("EXEC: %s %r", cached, params)
        try:
            self._execute(cached, params)
        except Exception as error:
            self.sqllog.info("EXCEPTION: %s", error)
            raise
        finally:
            self.in_transaction = True

    def ddl(self, stmt):
        stmt = self.transform_stmt(stmt)
        self.sqllog.info("DDL: %s", stmt)
        try:
            self.cursor().execute(stmt)
        except Exception as error:
            self.sqllog.info("EXCEPTION: %s", error)
            raise
        if self.config.get("ddl_implicit_commit") == "false":
            self.commit()
        else:
            self.in_transaction = False

    def selectrow(self, stmt, params=()):
        self.sql(stmt, params)
        ret = self.cursor().fetchone()
        self.sqllog.debug("FETCH: %s", ret)
        return ret

    def _selectall(self, stmt, params=()):
        self.sql(stmt, params)
        ret = self.cursor().fetchall()
        self.sqllog.debug("FETCHALL: %s", ret)
        return ret

    def _new_id_update(self, key):
        """
        Allocate a synthetic identifier by updating a table.
        """
        while True:
            row = self.selectrow(
                f"SELECT nextid FROM {self.prefix}sequences WHERE sequence_key = ?",
                (key,),
            )
            if row is None:
                raise Exception(f"Sequence {key} does not exist")

            ret = row[0]
            self.sql(
                f"UPDATE {self.prefix}sequences SET nextid = nextid + 1 \
                    WHERE sequence_key = ? AND nextid = ?",
                (key, ret),
            )
            if self.cursor().rowcount == 1:
                return ret
            self.log.info("Contention on %ssequences %s:%d", self.prefix, key, ret)

    def _get_sequence_initial_value(self, key):
        (ret,) = self.selectrow(f"SELECT MAX({key}_id) FROM {key}")
        ret = 1 if ret is None else ret + 1
        return ret

    def _create_sequence_update(self, key):
        self.commit()
        ret = self._get_sequence_initial_value(key)
        try:
            self.sql(
                f"INSERT INTO {self.prefix}sequences (sequence_key, nextid) VALUES (?, ?) \
                    ON CONFLICT (sequence_key) DO NOTHING",
                (key, ret),
            )
        except self.module.DatabaseError as error:
            self.rollback()
            try:
                self.ddl(
                    f"CREATE TABLE {self.prefix}sequences ("
                    f"sequence_key VARCHAR(100) NOT NULL PRIMARY KEY,"
                    f"nextid NUMERIC(30))"
                )
            except Exception as error:
                self.rollback()
                raise error
            self.sql(
                f"INSERT INTO {self.prefix}sequences (sequence_key, nextid) VALUES (?, ?) \
                    ON CONFLICT (sequence_key) DO NOTHING",
                (key, ret),
            )

    def _drop_sequence_update(self, key):
        self.commit()
        self.sql(f"DELETE FROM {self.prefix}sequences WHERE sequence_key = ?", (key,))
        self.commit()

    def _new_id_oracle(self, key):
        (ret,) = self.selectrow(f"SELECT {key}_seq.NEXTVAL FROM DUAL")
        return ret

    def _create_sequence(self, key):
        self.ddl(
            f"CREATE SEQUENCE {key}_seq START WITH {self._get_sequence_initial_value(key)}"
        )

    def _drop_sequence(self, key):
        self.ddl(f"DROP SEQUENCE {(key,)}_seq")

    def _new_id_nvf(self, key):
        (ret,) = self.selectrow(f"SELECT NEXT VALUE FOR {key}_seq")
        return ret

    def _new_id_postgres(self, key):
        (ret,) = self.selectrow(f"SELECT NEXTVAL('{key}_seq')")
        return ret

    def _create_sequence_db2(self, key):
        self.commit()
        try:
            rows = self.selectall(f"SELECT 1 FROM {self.prefix}dual")
            if len(rows) != 1:
                self.sql(f"INSERT INTO {self.prefix}dual(x) VALUES ('X')")
        except self.module.DatabaseError:
            self.rollback()
            self.drop_table_if_exists(f"{self.prefix}dual")
            self.ddl(f"CREATE TABLE {self.prefix}dual (x CHAR(1))")
            self.sql(f"INSERT INTO {self.prefix}dual(x) VALUES ('X')")
            self.log.info("Created silly table %sdual", self.prefix)
        self._create_sequence(key)

    def _new_id_db2(self, key):
        (ret,) = self.selectrow(f"SELECT NEXTVAL FOR {key}_seq FROM {self.prefix}dual")
        return ret

    def _create_sequence_mysql(self, key):
        self.ddl(
            f"CREATE TABLE {key}_seq (id BIGINT AUTO_INCREMENT PRIMARY KEY) \
                AUTO_INCREMENT={self._get_sequence_initial_value(key)}"
        )

    def _drop_sequence_mysql(self, key):
        self.ddl(f"DROP TABLE {key}_seq")

    def _new_id_mysql(self, key):
        self.sql(f"INSERT INTO {key}_seq () VALUES ()")
        (ret,) = self.selectrow("SELECT LAST_INSERT_ID()")
        if ret % 1000 == 0:
            self.sql(f"DELETE FROM {key}_seq WHERE id < ?", (ret,))
        return ret

    def commit(self):
        self.sqllog.info("COMMIT")
        self.conn().commit()
        self.in_transaction = False

    def rollback(self):
        if self.module is None:
            return
        self.sqllog.info("ROLLBACK")
        try:
            self.conn().rollback()
            self.in_transaction = False
        except self.module.OperationalError as error:
            self.log.warning("Reconnecting after rollback error: %s", error)
            self.reconnect()

    def close(self):
        conn = self._conn
        if conn is not None:
            self.sqllog.info("CLOSE")
            conn.close()
            self._conn = None
            self._cursor = None

    def configure(self):
        self.configure_ddl_implicit_commit()
        self.configure_create_table_epilogue()
        self.configure_max_varchar()
        self.configure_max_precision()
        self.configure_clob_type()
        self.configure_binary_type()
        self.configure_int_type()
        self.configure_sequence_type()
        self.configure_limit_style()
        self.configure_concat_style()

        return self.config

    def configure_binary_type(self):
        defaults = (
            ["binary", "bytearray", "buffer", "hex", "pg-bytea"]
            if self.binary_type is None
            else [self.binary_type]
        )
        tests = (
            defaults
            if self.config.get("binary_type") is None
            else [self.config["binary_type"]]
        )

        for val in tests:
            self.config["binary_type"] = val
            self._set_flavour()
            if self._test_binary_type():
                self.log.info("binary_type=%s", val)
                return

        raise Exception(
            "No known binary data representation works"
            if len(tests) > 1
            else "Binary type " + tests[0] + " fails test"
        )

    def configure_int_type(self):
        defaults = (
            ["int", "decimal", "str"] if self.int_type is None else [self.int_type]
        )

        tests = (
            defaults
            if self.config.get("int_type") is None
            else [self.config["int_type"]]
        )

        for val in tests:
            self.config["int_type"] = val
            self._set_flavour()
            if self._test_int_type():
                self.log.info("int_type=%s", val)
                return
        raise Exception(
            "No known large integer representation works"
            if len(tests) > 1
            else "Integer type " + tests[0] + " fails test"
        )

    def configure_sequence_type(self):
        for val in ["nvf", "oracle", "postgres", "mysql", "db2", "update"]:
            self.config["sequence_type"] = val
            self._set_flavour()
            if self._test_sequence_type():
                self.log.info("sequence_type=%s", val)
                return
        raise Exception("No known sequence type works")

    def _drop_if_exists(self, otype, name):
        try:
            self.sql("DROP " + otype + " IF EXISTS " + name)
            self.commit()
        except self.module.DatabaseError:
            self.rollback()

    def drop_table_if_exists(self, obj):
        self._drop_if_exists("TABLE", obj)

    def drop_view_if_exists(self, obj):
        self._drop_if_exists("VIEW", obj)

    def drop_sequence_if_exists(self, key):
        try:
            self.drop_sequence(key)
        except self.module.DatabaseError:
            self.rollback()

    def drop_column_if_exists(self, table, column):
        try:
            self.ddl("ALTER TABLE " + table + " DROP COLUMN " + column)
        except self.module.DatabaseError:
            self.rollback()

    def configure_ddl_implicit_commit(self):
        if "create_table_epilogue" not in self.config:
            self.config["create_table_epilogue"] = ""
        for val in ["true", "false"]:
            self.config["ddl_implicit_commit"] = val
            self._set_flavour()
            if self._test_ddl():
                self.log.info("ddl_implicit_commit=%s", val)
                return
        raise Exception("Can not test for DDL implicit commit.")

    def _test_ddl(self):
        """Test whether DDL performs implicit commit."""
        self.drop_table_if_exists(f"{self.prefix}test_1")
        try:
            self.ddl(
                f"CREATE TABLE {self.prefix}test_1 ("
                f"{self.prefix}test_1_id NUMERIC(12) NOT NULL PRIMARY KEY, "
                f"foo VARCHAR(10))"
            )
            self.rollback()
            self.selectall(
                f"SELECT MAX({self.prefix}test_1_id) FROM {self.prefix}test_1"
            )
            return True
        except self.module.DatabaseError:
            self.rollback()
            return False
        except Exception:
            self.rollback()
            return False
        finally:
            self.drop_table_if_exists(f"{self.prefix}test_1")

    def configure_create_table_epilogue(self):
        for val in ["", " ENGINE=InnoDB"]:
            self.config["create_table_epilogue"] = val
            self._set_flavour()
            if self._test_transaction():
                self.log.info("create_table_epilogue='%s'", val)
                return
        raise Exception("Can not create a transactional table.")

    def _test_transaction(self):
        """Test whether CREATE TABLE needs ENGINE=InnoDB for rollback."""
        self.drop_table_if_exists(f"{self.prefix}test_1")
        try:
            self.ddl(f"CREATE TABLE {self.prefix}test_1 (a NUMERIC(12))")
            self.sql(f"INSERT INTO {self.prefix}test_1 (a) VALUES (4)")
            self.commit()
            self.sql(f"INSERT INTO {self.prefix}test_1 (a) VALUES (5)")
            self.rollback()
            data = [
                int(row[0])
                for row in self.selectall(f"SELECT a FROM {self.prefix}test_1")
            ]
            return data == [4]
        except self.module.DatabaseError:
            self.rollback()
            return False
        except Exception:
            self.rollback()
            return False
        finally:
            self.drop_table_if_exists(f"{self.prefix}test_1")

    def configure_max_varchar(self):
        """Find the maximum VARCHAR width, up to 0xffffffff"""
        low = 0
        high = 1 << 32
        mid = high - 1
        self.config["max_varchar"] = str(mid)
        self.drop_table_if_exists(f"{self.prefix}test_1")
        while True:
            self.drop_table_if_exists(f"{self.prefix}test_1")
            try:
                self.ddl(
                    f"CREATE TABLE {self.prefix}test_1 (a VARCHAR({mid}), b VARCHAR({mid}))"
                )
                self.sql(f"INSERT INTO {self.prefix}test_1 (a, b) VALUES ('x', 'y')")
                row = self.selectrow(f"SELECT a, b FROM {self.prefix}test_1")
                if [val for val in row] == ["x", "y"]:
                    low = mid
                else:
                    high = mid
            except self.module.DatabaseError:
                self.rollback()
                high = mid
            except Exception:
                self.rollback()
                high = mid
            if low + 1 == high:
                self.config["max_varchar"] = str(low)
                self.log.info("max_varchar=%s", self.config["max_varchar"])
                break
            mid = int((low + high) / 2)
        self.drop_table_if_exists(f"{self.prefix}test_1")

    def configure_max_precision(self):
        self.config["max_precision"] = ""  # XXX

    def configure_clob_type(self):
        """Find the name of the CLOB type, if any."""
        long_str = "x" * 10000
        self.drop_table_if_exists(f"{self.prefix}test_1")
        for val in ["CLOB", "LONGTEXT", "TEXT", "LONG"]:
            try:
                self.ddl(f"CREATE TABLE {self.prefix}test_1 (a {val})")
                self.sql(
                    f"INSERT INTO {self.prefix}test_1 (a) VALUES (?)",
                    (self.binin(long_str),),
                )
                out = self.selectrow(f"SELECT a FROM {self.prefix}test_1")[0]
                if self.binout(out) == long_str:
                    self.config["clob_type"] = val
                    self.log.info("clob_type=%s", val)
                    return
                else:
                    self.log.debug("out=%s", repr(out))
            except self.module.DatabaseError:
                self.rollback()
            except Exception:
                try:
                    self.rollback()
                except Exception:
                    # Fetching a CLOB really messes up Easysoft ODBC Oracle.
                    self.reconnect()
                    raise
            finally:
                self.drop_table_if_exists(f"{self.prefix}test_1")
        self.log.info("No native type found for CLOB.")
        self.config["clob_type"] = NO_CLOB

    def _test_binary_type(self):
        self.drop_table_if_exists(f"{self.prefix}test_1")
        try:
            bit_type = "BINARY(32)"
            # XXX The 10000 should be configurable: max_desired_binary?
            var_bit_type = "VARBINARY(10000))"

            if self.config["binary_type"] == "pg-bytea":
                bit_type = "bytea"
                var_bit_type = "bytea"

            self.ddl(
                f"CREATE TABLE {self.prefix}test_1 ("
                f"test_id NUMERIC(2) NOT NULL PRIMARY KEY,"
                f"test_bit {bit_type},"
                f"test_varbit {var_bit_type})"
            )
            val = "".join(map(chr, range(0, 256, 8)))
            revin = self.revin(val)
            binin = self.binin(val)
            self.sql(
                f"INSERT INTO {self.prefix}test_1 (test_id, test_bit, test_varbit) \
                    VALUES (?, ?, ?)",
                (1, revin, binin),
            )
            (bit, vbit) = self.selectrow(
                f"SELECT test_bit, test_varbit FROM {self.prefix}test_1"
            )
            binout = self.binout(vbit)
            revout = self.revout(bit)
            return binout == val and revout == binout
        except self.module.DatabaseError:
            self.rollback()
            return False
        except Exception:
            self.rollback()
            return False
        finally:
            self.drop_table_if_exists(f"{self.prefix}test_1")

    def _test_int_type(self):
        self.drop_view_if_exists(f"{self.prefix}test_v1")
        self.drop_table_if_exists(f"{self.prefix}test_1")
        try:
            self.ddl(
                f"""
                CREATE TABLE {self.prefix}test_1 (
                    test_id NUMERIC(2) NOT NULL PRIMARY KEY,
                    i1 NUMERIC(28), i2 NUMERIC(28), i3 NUMERIC(28))"""
            )
            # XXX No longer needed?
            self.ddl(
                f"""
                CREATE VIEW {self.prefix}test_v1 AS
                SELECT test_id,
                       i1 i1_approx,
                       i1,
                       i2
                  FROM {self.prefix}test_1"""
            )
            val_1 = 2099999999999999
            val_2 = 1234567890
            val_3 = 12345678901234567890
            self.sql(
                f"INSERT INTO {self.prefix}test_1 (test_id, i1, i2, i3)"
                " VALUES (?, ?, ?, ?)",
                (1, self.intin(val_1), val_2, self.intin(val_3)),
            )
            self.commit()
            prod, ord_1 = self.selectrow(
                f"SELECT i1_approx * i2, i1 FROM {self.prefix}test_v1"
            )
            prod = int(prod)
            ord_1 = int(ord_1)
            if (
                prod < val_1 * val_2 * 1.0001
                and prod > val_1 * val_2 * 0.9999
                and ord_1 == val_1
            ):
                return True
            return False
        except self.module.DatabaseError:
            self.rollback()
            return False
        except Exception:
            self.rollback()
            return False
        finally:
            self.drop_view_if_exists(f"{self.prefix}test_v1")
            self.drop_table_if_exists(f"{self.prefix}test_1")

    def _test_sequence_type(self):
        self.drop_table_if_exists(f"{self.prefix}test_1")
        self.drop_sequence_if_exists(f"{self.prefix}test_1")

        try:
            self.ddl(
                f"""
                CREATE TABLE {self.prefix}test_1 (
                    {self.prefix}test_1_id NUMERIC(12) NOT NULL PRIMARY KEY,
                    foo VARCHAR(10)
                )"""
            )
            self.create_sequence(f"{self.prefix}test_1")
            id1 = self.new_id(f"{self.prefix}test_1")
            id2 = self.new_id(f"{self.prefix}test_1")
            if int(id1) != int(id2):
                return True
            return False
        except self.module.DatabaseError:
            self.rollback()
            return False
        except Exception:
            self.rollback()
            return False
        finally:
            self.drop_table_if_exists(f"{self.prefix}test_1")
            try:
                self.drop_sequence(f"{self.prefix}test_1")
            except self.module.DatabaseError:
                self.rollback()

    def configure_limit_style(self):
        for val in ["native", "emulated"]:
            self.config["limit_style"] = val
            self._set_flavour()
            if self._test_limit_style():
                self.log.info("limit_style=%s", val)
                return
        raise Exception("Can not emulate LIMIT.")

    def _test_limit_style(self):
        self.drop_table_if_exists(f"{self.prefix}test_1")
        try:
            self.ddl(
                f"""
                CREATE TABLE {self.prefix}test_1 (
                    {self.prefix}test_1_id NUMERIC(12) NOT NULL PRIMARY KEY
                )"""
            )
            for elem in (2, 4, 6, 8):
                self.sql(
                    f"INSERT INTO {self.prefix}test_1 ({self.prefix}test_1_id) VALUES (?)",
                    (elem,),
                )
            rows = self.selectall(
                f"""
                SELECT {self.prefix}test_1_id
                FROM {self.prefix}test_1
                ORDER BY {self.prefix}test_1_id
                LIMIT 3"""
            )
            return [int(row[0]) for row in rows] == [2, 4, 6]
        except self.module.DatabaseError:
            self.rollback()
            return False
        except Exception:
            self.rollback()
            return False
        finally:
            self.drop_table_if_exists(f"{self.prefix}test_1")

    def configure_concat_style(self):
        for val in ["ansi", "mysql"]:
            self.config["concat_style"] = val
            self._set_flavour()
            if self._test_concat_style():
                self.log.info("concat_style=%s", val)
                return
        raise Exception("Can not find suitable concatenation style.")

    def _test_concat_style(self):
        try:
            rows = self.selectall(
                """
                SELECT 'foo' || ? || 'baz' AS String1,
                    ? || 'foo' || ? AS String2
                """,
                ("bar", "baz", "bar"),
            )
            self.log.info(str(rows))
            if rows[0][0] == "foobarbaz" and rows[0][1] == "bazfoobar":
                return True
        except Exception:
            pass

        self.rollback()
        return False
