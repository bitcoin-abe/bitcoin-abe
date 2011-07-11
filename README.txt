Abe: a free block chain browser for Bitcoin-based currencies.
Copyright(C) 2011 by John Tobey <John.Tobey@gmail.com>
License: GNU Affero General Public License, see the file LICENSE.txt.
Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.

Welcome to Abe!

This software reads the Bitcoin block file, transforms and loads the
data into a database, and presents a web interface similar to the
original Block Explorer by theymos, http://blockexplorer.com/.

Abe draws inspiration from BlockExplorer.com and seeks some level of
compatibility with it but uses a completely new implementation.

This program depends on Python Crypto modules (Debian package
python-crypto) and a database such as SQLite (python-pysqlite2) or
PostgreSQL.  Other SQL databases may work with minor changes.  You
will need a copy of the block file (blk0001.dat in your Bitcoin
directory).  You may let Abe read the block file while Bitcoin runs.

The GNU Affero General Public License requires whoever modifies this
code and runs it on a server to make the modified code available to
users of the server.  You may do this by forking the Github project
(if you received this code from Github.com), keeping your
modifications in the new project, and linking to it in the page
template.  Or you may wish to satisfy the requirement by simply
passing "--auto-agpl" to "abe.py".  This option makes all files in the
directory containing abe.py and its subdirectories available to
clients.  See the comments in abe.conf for more information.

For usage, run "abe.py --help" and see the comments in abe.conf.  By
default, Abe reads your Bitcoin blk0001.dat file and runs a chain
viewer over FastCGI.  BUG: reading the block file takes far too long,
hours on PostgreSQL and days on SQLite3.  However, Abe remembers where
it stopped reading and starts more quickly the second time.

To run the built-in HTTP server instead of FastCGI, add "--port 2750"
or a TCP port number of your choosing.

To explore Namecoin (or a chain with data somewhere other than the
default Bitcoin directory) pass, e.g., "--datadir ~/.namecoin".  Note
that this software is currently unaware of name transactions.

See `abe.py --help` for examples of how to persist the data, greatly
reducing start time.

PostgreSQL on Debian/Ubuntu:
  apt-get install postgresql python-psycopg2
  sudo -u postgres createdb abe
  # Replace USER with your Unix user name:
  sudo -u postgres createuser USER
  # Replace 8.4 with the PostgreSQL version:
  sudo sh -c "echo local abe USER ident >> /etc/postgresql/8.4/main/pg_hba.conf"
  service postgresql reload

Please see TODO.txt for a list of what is not yet implemented but
would like to be.

Forum thread: https://forum.bitcoin.org/index.php?topic=16141.0
Donations appreciated: 1PWC7PNHL1SgvZaN7xEtygenKjWobWsCuf (BTC)
NJ3MSELK1cWnqUa6xhF2wUYAnz3RSrWXcK (NMC)
