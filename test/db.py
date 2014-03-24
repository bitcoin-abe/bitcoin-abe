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
import os
import subprocess
import Abe.util

def testdb_params():
    dbs = os.environ.get('ABE_TEST_DB')
    if dbs is not None:
        return dbs.split()
    if os.environ.get('ABE_TEST') == 'quick':
        return ['sqlite3']
    return ['sqlite3', 'mysql', 'postgres']

@pytest.fixture(scope="module", params=testdb_params())
def testdb(request):
    db = create(request.param)
    request.addfinalizer(db.delete)
    return db

def create(dbtype=None):
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
        db.cmdline = ['--dbtype', dbtype, '--connect-args', json.dumps(connect_args)]
        db.createdb()

    def createdb(db):
        store, argv = Abe.util.CmdLine(db.cmdline).init()
        db.store = store

    def dropdb(db):
        db.store.close()

    def delete(db):
        db.dropdb()

class SqliteDB(DB):
    def __init__(db, connect_args):
        DB.__init__(db, 'sqlite3', connect_args)

    def delete(db):
        DB.delete(db)
        os.unlink(db.connect_args)

class SqliteMemoryDB(SqliteDB):
    def __init__(db):
        SqliteDB.__init__(db, ':memory:')

    def delete(db):
        DB.delete(db)

class MysqlDB(DB):
    def __init__(db):
        import tempfile
        db.tmpdir = py.path.local(tempfile.mkdtemp(prefix='abe-test'))
        print("Created temporary directory %s" % db.tmpdir)
        try:
            db._install_mysql()
        except Exception as e:
            #print("EXCEPTION %s" % e)
            db._delete_tmpdir()
            raise
        DB.__init__(db, 'MySQLdb', {'user': 'abe', 'passwd': 'Bitcoin', 'db': 'abe', 'unix_socket': db.socket})

    def _install_mysql(db):
        db.tmpdir.ensure_dir('tmp')
        db.socket = str(db.tmpdir.join('mysql.sock'))
        mycnf = db.tmpdir.join('my.cnf')
        mycnf.write('[mysqld]\n'
                    'datadir=%(tmpdir)s\n'
                    #'log\n'
                    #'log-error\n'
                    'skip-networking\n'
                    'socket=mysql.sock\n'
                    'pid-file=mysqld.pid\n'
                    'tmpdir=tmp\n' % { 'tmpdir': db.tmpdir })
        subprocess.check_call(['mysql_install_db', '--defaults-file=' + str(mycnf)])
        db.server = subprocess.Popen(['mysqld', '--defaults-file=' + str(mycnf)])
        import time
        time.sleep(5)
        conn = db._connect_root()
        cur = conn.cursor()
        cur.execute("CREATE USER 'abe'@'localhost' IDENTIFIED BY 'Bitcoin'")
        conn.close()

    def _connect_root(db):
        MySQLdb = pytest.importorskip('MySQLdb')
        return MySQLdb.connect(unix_socket=db.socket, user='root')

    def createdb(db):
        conn = db._connect_root()
        cur = conn.cursor()
        cur.execute('CREATE DATABASE abe')
        cur.execute("GRANT ALL ON abe.* TO 'abe'@'localhost'")
        conn.close()
        DB.createdb(db)

    def dropdb(db):
        DB.dropdb(db)
        conn = db._connect_root()
        cur = conn.cursor()
        cur.execute('DROP DATABASE abe')
        conn.close()

    def _delete_tmpdir(db):
        db.tmpdir.remove()
        print("Deleted temporary directory %s" % db.tmpdir)

    def delete(db):
        DB.delete(db)
        try:
            subprocess.check_call(['mysqladmin', '-S', db.socket, '-u', 'root', 'shutdown'])
            db.server.wait()
        finally:
            db._delete_tmpdir()

class PostgresDB(DB):
    def __init__(db):
        pytest.skip("not implemented")
