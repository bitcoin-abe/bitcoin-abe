import Abe.util

def create():
    return SqliteMemoryDB()

class SqliteMemoryDB(object):
    def new_store(db):
        cmdline = Abe.util.CmdLine([
                '--dbtype', 'sqlite3',
                '--connect-args', ':memory:'])
        store, argv = cmdline.init()
        return store
