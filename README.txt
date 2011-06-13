Another Block Explorer for Bitcoin.
Copyright(C) 2011 by John Tobey <John.Tobey@gmail.com>
License: GNU Affero Public License, see the file LICENSE.txt.
Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.

This program depends on Python Crypto modules (Debian package
python-crypto) and either Sqlite (python-pysqlite2) or PostgreSQL.
Other RDBMSs may work.

For usage, run "abe.py".  By default, this program reads your Bitcoin
blk0001.dat file and runs a block explorer on http://localhost:8888/.
BUG: reading the block file takes far too long, hours.

See `abe.py --help` for examples of how to persist the data, greatly
reducing start time.
