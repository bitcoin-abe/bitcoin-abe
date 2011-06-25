Another Block Explorer for Bitcoin.
Copyright(C) 2011 by John Tobey <John.Tobey@gmail.com>
License: GNU Affero General Public License, see the file LICENSE.txt.
Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.

Welcome to ABE!

This software reads the Bitcoin block file, transforms and loads the
data into a database, and presents a web interface similar to the
original Block Explorer by theymos, http://blockexplorer.com/.

ABE draws inspiration from BlockExplorer.com and seeks some level of
compatibility with it but uses a completely new implementation.

This program depends on Python Crypto modules (Debian package
python-crypto) and either Sqlite (python-pysqlite2) or PostgreSQL.
Other RDBMSs may work.

For usage, run "abe.py --help".  By default, ABE reads your Bitcoin
blk0001.dat file and runs a block explorer over FastCGI.  BUG: reading
the block file takes far too long, hours.  However, ABE remembers
where it stopped reading and starts more quickly the second time.

To run the built-in HTTP server instead of FastCGI, add "--port 2750"
or a TCP port number of your choosing.

To explore Namecoin (or a chain with data somewhere other than the
default Bitcoin directory) pass, e.g., "--datadir ~/.namecoin".  Note
that this software is currently unaware of name transactions.

See `abe.py --help` for examples of how to persist the data, greatly
reducing start time.

Please see TODO.txt for a list of what is not yet implemented but
would like to be.

Forum thread: https://forum.bitcoin.org/index.php?topic=16141.0
Donations appreciated: 1PWC7PNHL1SgvZaN7xEtygenKjWobWsCuf (BTC)
NJ3MSELK1cWnqUa6xhF2wUYAnz3RSrWXcK (NMC)
