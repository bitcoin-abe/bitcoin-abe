# Copyright(C) 2014 by Abe developers.

# db.py: temporary database for automated testing

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

from __future__ import print_function
import pytest
import py.path
import json
import contextlib
import os
import subprocess
import Abe.util

def testdb_params():
    dbs = os.environ.get('ABE_TEST_DB')
    if dbs is not None:
        return dbs.split()
    if os.environ.get('ABE_TEST') == 'quick':
        return ['sqlite']
    return ['sqlite', 'mysql', 'postgres']

# XXX
def ignore_errors(thunk):
    def doit():
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
    if dbtype in (None, 'sqlite3', 'sqlite'):
        return SqliteMemoryDB()
    if dbtype in ('mysql', 'MySQLdb'):
        return MysqlDB()
    if dbtype in ('psycopg2', 'postgres'):
        return PostgresDB()
    pytest.skip('Unknown dbtype: %s' % dbtype)

class DB(object):
    def __init__(db, dbtype, connect_args):
        db.dbtype = dbtype
        db.connect_args = connect_args
        db.cmdline = ('--dbtype', dbtype, '--connect-args', json.dumps(connect_args))
        db.store = None

    def createdb(db):
        pass

    def load(db, *args):
        db.createdb()
        db.store, argv = Abe.util.CmdLine(db.cmdline + args).init()
        assert len(argv) == 0
        db.store.catch_up()
        return db.store

    def dropdb(db):
        if db.store:
            db.store.close()

    def delete(db):
        pass

class SqliteDB(DB):
    def __init__(db, connect_args):
        DB.__init__(db, 'sqlite3', connect_args)

    def delete(db):
        DB.delete(db)
        os.unlink(db.connect_args)

class SqliteMemoryDB(SqliteDB):
    def __init__(db):
        #print("SqliteMemoryDB.__init__")
        SqliteDB.__init__(db, ':memory:')

    def delete(db):
        DB.delete(db)
        #print("SqliteMemoryDB.delete")

class ServerDB(DB):
    def __init__(db, dbtype):
        pytest.importorskip(dbtype)
        import tempfile
        db.installation_dir = py.path.local(tempfile.mkdtemp(prefix='abe-test-'))
        print("Created temporary directory %s" % db.installation_dir)
        try:
            db.server = db.install_server()
        except Exception as e:
            #print("EXCEPTION %s" % e)
            db._delete_tmpdir()
            pytest.skip(e)
            raise
        DB.__init__(db, dbtype, db.get_connect_args())

    def install_server(db):
        pass

    @contextlib.contextmanager
    def root(db):
        conn = db.connect_as_root()
        cur = conn.cursor()
        try:
            yield cur
        except:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def delete(db):
        try:
            db.shutdown()
            db.server.wait()
        finally:
            db._delete_tmpdir()
            pass

    def _delete_tmpdir(db):
        if os.environ.get('ABE_TEST_KEEP_TMPDIR', '') == '':
            db.installation_dir.remove()
            print("Deleted temporary directory %s" % db.installation_dir)

class MysqlDB(ServerDB):
    def __init__(db):
        ServerDB.__init__(db, 'MySQLdb')

    def get_connect_args(db):
        return {'user': 'abe', 'passwd': 'Bitcoin', 'db': 'abe', 'unix_socket': db.socket}

    def install_server(db):
        db.socket = str(db.installation_dir.join('mysql.sock'))
        db.installation_dir.ensure_dir('tmp')
        mycnf = db.installation_dir.join('my.cnf')
        mycnf.write('[mysqld]\n'
                    'datadir=%(installation_dir)s\n'
                    #'log\n'
                    #'log-error\n'
                    'skip-networking\n'
                    'socket=mysql.sock\n'
                    'pid-file=mysqld.pid\n'
                    'tmpdir=tmp\n' % { 'installation_dir': db.installation_dir })
        subprocess.check_call(['mysql_install_db', '--defaults-file=' + str(mycnf)])
        server = subprocess.Popen(['mysqld', '--defaults-file=' + str(mycnf)])
        import time, MySQLdb
        tries = 30
        for t in range(tries):
            try:
                with db.root() as cur:
                    cur.execute("CREATE USER 'abe'@'localhost' IDENTIFIED BY 'Bitcoin'")
                    return server
            except MySQLdb.OperationalError as e:
                if t+1 == tries:
                    raise e
            time.sleep(1)

    def connect_as_root(db):
        import MySQLdb
        conn = MySQLdb.connect(unix_socket=db.socket, user='root')
        return conn

    def createdb(db):
        with db.root() as cur:
            cur.execute('CREATE DATABASE abe')
            cur.execute("GRANT ALL ON abe.* TO 'abe'@'localhost'")
        DB.createdb(db)

    def dropdb(db):
        DB.dropdb(db)
        with db.root() as cur:
            cur.execute('DROP DATABASE abe')

    def shutdown(db):
        subprocess.check_call(['mysqladmin', '-S', db.socket, '-u', 'root', 'shutdown'])

class PostgresDB(ServerDB):
    def __init__(db):
        ServerDB.__init__(db, 'psycopg2')

    def get_connect_args(db):
        return {'user': 'abe', 'password': 'Bitcoin', 'database': 'abe', 'host': str(db.installation_dir)}

    def install_server(db):
        db.bindir = subprocess.Popen(['pg_config', '--bindir'], stdout=subprocess.PIPE).communicate()[0].rstrip()
        subprocess.check_call([
                os.path.join(db.bindir, 'initdb'),
                '-D', str(db.installation_dir),
                '-U', 'postgres'])
        server = subprocess.Popen([
                os.path.join(db.bindir, 'postgres'),
                '-D', str(db.installation_dir),
                '-c', 'listen_addresses=',
                '-c', 'unix_socket_directory=.'])

        import time, psycopg2
        tries = 30
        for t in range(tries):
            try:
                with db.root() as cur:
                    cur.execute("COMMIT")  # XXX
                    cur.execute("CREATE USER abe UNENCRYPTED PASSWORD 'Bitcoin'")
                    cur.execute("COMMIT")
                return server
            except psycopg2.OperationalError as e:
                if t+1 == tries:
                    raise e
            time.sleep(1)

    def connect_as_root(db):
        import psycopg2
        conn = psycopg2.connect(host=str(db.installation_dir), user='postgres')
        return conn

    def createdb(db):
        with db.root() as cur:
            cur.execute("COMMIT")  # XXX
            cur.execute('CREATE DATABASE abe')
            cur.execute("GRANT ALL ON DATABASE abe TO abe")
            cur.execute("COMMIT")
        DB.createdb(db)

    def dropdb(db):
        DB.dropdb(db)
        with db.root() as cur:
            cur.execute("COMMIT")  # XXX
            cur.execute('DROP DATABASE abe')
            cur.execute("COMMIT")

    def shutdown(db):
        subprocess.check_call([
                os.path.join(db.bindir, 'pg_ctl'), 'stop',
                '-D', str(db.installation_dir),
                '-m', 'immediate'])
