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

import pytest
import os
import Abe.util

def testdb_params():
    return [None]

@pytest.fixture(scope="module", params=testdb_params())
def testdb(request):
    db = create(request.param)
    request.addfinalizer(db.delete)
    return db

def create(dbtype=None):
    return SqliteDB()

class DB(object):
    def __init__(db, cmdline):
        store, argv = Abe.util.CmdLine(cmdline).init()
        db.store = store

    def delete(db):
        pass

class SqliteDB(DB):
    def __init__(db):
        db.connect_args = os.environ.get('ABE_TEST_DB', ':memory:')
        db.cmdline = ['--dbtype', 'sqlite3', '--connect-args', db.connect_args]
        DB.__init__(db, db.cmdline)

    def delete(db):
        if db.connect_args != ':memory:':
            os.unlink(db.connect_args)
