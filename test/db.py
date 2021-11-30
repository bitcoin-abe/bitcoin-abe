# Copyright(C) 2014 by Abe developers.

"""db.py: temporary database for automated testing"""

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

import json
import contextlib
import os
import tempfile
from pathlib import Path
import subprocess
import time
import MySQLdb
import psycopg2
import pytest
from Abe.data_store import CmdLine


def testdb_params():
    """Provides a list of the database server types to be tested."""
    dbs = os.environ.get("ABE_TEST_DB")
    if dbs is not None:
        return dbs.split()
    if os.environ.get("ABE_TEST") == "quick":
        return ["sqlite"]
    return ["sqlite", "mysql", "postgres"]


# XXX
def ignore_errors(thunk):
    def doit():
        # pylint: disable=broad-except
        try:
            thunk()
        except Exception:
            pass

    return doit


@pytest.fixture(scope="module")
def testdb(request, db_server):
    request.addfinalizer(ignore_errors(db_server.dropdb))
    return db_server


def create_server(dbtype=None):
    if dbtype in (None, "sqlite3", "sqlite"):
        return SqliteMemoryDB()
    if dbtype in ("mysql", "MySQLdb"):
        return MysqlDB()
    if dbtype in ("psycopg2", "postgres"):
        return PostgresDB()
    pytest.skip(f"Unknown dbtype: {dbtype}")


class DB:
    def __init__(self, dbtype, connect_args):
        self.dbtype = dbtype
        self.connect_args = connect_args
        self.cmdline = ("--dbtype", dbtype, "--connect-args", json.dumps(connect_args))
        self.store = None

    def createdb(self):
        pass

    def load(self, *args):
        self.createdb()
        self.store, argv = CmdLine(self.cmdline + args).init()
        assert len(argv) == 0
        self.store.catch_up()
        return self.store

    def dropdb(self):
        if self.store:
            self.store.close()

    def delete(self):
        pass


class SqliteDB(DB):
    def __init__(self, connect_args):
        DB.__init__(self, "sqlite3", connect_args)

    def delete(self):
        DB.delete(self)
        os.unlink(self.connect_args)


class SqliteMemoryDB(SqliteDB):
    def __init__(self):
        # print("SqliteMemoryDB.__init__")
        SqliteDB.__init__(self, ":memory:")

    def delete(self):
        DB.delete(self)
        # print("SqliteMemoryDB.delete")


class ServerDB(DB):
    # pylint: disable=no-member
    def __init__(self, dbtype):
        pytest.importorskip(dbtype)
        self.installation_dir = tempfile.mkdtemp(prefix="abe-test-") + "/"

        print(f"Created temporary directory {self.installation_dir}")
        try:
            self.server = self.install_server()
        except Exception:
            self._delete_tmpdir()
            raise
        super().__init__(dbtype, self.get_connect_args())

    @contextlib.contextmanager
    def root(self):
        conn = self.connect_as_root()
        cur = conn.cursor()
        try:
            yield cur
        except:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def delete(self):
        try:
            self.shutdown()
            self.server.wait()
        finally:
            self._delete_tmpdir()

    def _delete_tmpdir(self):
        if os.environ.get("ABE_TEST_KEEP_TMPDIR", "") == "":
            os.rmdir(self.installation_dir)
            print(f"Deleted temporary directory {self.installation_dir}")


class MysqlDB(ServerDB):
    """MySQL Test Server Class"""

    socket: str

    def __init__(self):
        super().__init__("MySQLdb")

    def get_connect_args(self):
        return {
            "user": "abe",
            "passwd": "Bitcoin",
            "db": "abe",
            "unix_socket": self.socket,
        }

    def install_server(self):
        self.socket = self.installation_dir + "/mysql.sock"
        Path(self.installation_dir + "/data").mkdir(exist_ok=True)
        Path(self.installation_dir + "/tmp").mkdir(exist_ok=True)
        Path(self.installation_dir + "/log").mkdir(exist_ok=True)

        mycnf = self.installation_dir + "/my.cnf"
        with open(mycnf, "w", encoding="UTF8") as mycnf:
            mycnf.write(
                "[mysqld]\n"
                + f"basedir={self.installation_dir}\n"
                + f"datadir={self.installation_dir}/data\n"
                # + "log\n"
                # + 'log-error\n'
                + "skip-networking\n"
                + "socket=mysql.sock\n"
                + "pid-file=mysqld.pid\n"
                + f"tmpdir={self.installation_dir}/tmp\n"
            )
            mycnf.close()
        subprocess.check_call(
            [
                "mysqld",
                "--defaults-file=" + mycnf.name,
                "--initialize",
                "-h",
                self.installation_dir + "/data",
            ]
        )
        server = subprocess.Popen(["mysqld", "--defaults-file=" + mycnf.name])
        tries = 30
        for i in range(tries):
            try:
                with self.root() as cur:
                    cur.execute("CREATE USER 'abe'@'localhost' IDENTIFIED BY 'Bitcoin'")
                    return server
            except MySQLdb.OperationalError as error:
                if i + 1 == tries:
                    raise error
            finally:
                time.sleep(1)

    def connect_as_root(self):
        conn = MySQLdb.connect(unix_socket=self.socket, user="root")
        return conn

    def createdb(self):
        with self.root() as cur:
            cur.execute("CREATE DATABASE abe")
            cur.execute("GRANT ALL ON abe.* TO 'abe'@'localhost'")
        DB.createdb(self)

    def dropdb(self):
        DB.dropdb(self)
        with self.root() as cur:
            cur.execute("DROP DATABASE abe")

    def shutdown(self):
        subprocess.check_call(
            ["mysqladmin", "-S", self.socket, "-u", "root", "shutdown"]
        )


class PostgresDB(ServerDB):
    """PostgreSQL Test Server Class"""

    def __init__(self):
        self.bindir = str(
            subprocess.Popen(["pg_config", "--bindir"], stdout=subprocess.PIPE)
            .communicate()[0]
            .rstrip(),
            "utf-8",
        )
        print(f"The binder is: {self.bindir}")
        super().__init__("psycopg2")

    def get_connect_args(self):
        return {
            "user": "abe",
            "password": "Bitcoin",
            "database": "abe",
            "host": str(self.installation_dir),
        }

    def install_server(self):
        subprocess.check_call(
            [
                os.path.join(self.bindir, "initdb"),
                "-D",
                str(self.installation_dir),
                "-U",
                "postgres",
            ]
        )
        server = subprocess.Popen(
            [
                os.path.join(self.bindir, "postgres"),
                "-D",
                str(self.installation_dir),
                "-h",  # hostname Specifies the IP host name or address
                "",  # An empty value specifies not listening on any IP addressesq
                "-k",  # directory Specifies the directory of the Unix-domain socket.
                ".",
            ]
        )

        tries = 30
        for i in range(tries):
            try:
                with self.root() as cur:
                    cur.execute("COMMIT")  # XXX
                    cur.execute("CREATE USER abe PASSWORD 'Bitcoin'")
                    cur.execute("COMMIT")
                return server
            except psycopg2.OperationalError as error:
                if i + 1 == tries:
                    raise error
            finally:
                time.sleep(1)

    def connect_as_root(self):
        conn = psycopg2.connect(host=str(self.installation_dir), user="postgres")
        return conn

    def createdb(self):
        with self.root() as cur:
            cur.execute("COMMIT")  # XXX
            cur.execute("CREATE DATABASE abe")
            cur.execute("GRANT ALL ON DATABASE abe TO abe")
            cur.execute("COMMIT")
        DB.createdb(self)

    def dropdb(self):
        DB.dropdb(self)
        with self.root() as cur:
            cur.execute("COMMIT")  # XXX
            cur.execute("DROP DATABASE abe")
            cur.execute("COMMIT")

    def shutdown(self):
        subprocess.check_call(
            [
                os.path.join(self.bindir, "pg_ctl"),
                "stop",
                "-D",
                str(self.installation_dir),
                "-m",
                "immediate",
            ]
        )
