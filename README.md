Blakecoin-Abe: a free block chain browser for the Blakecoin currencies.
https://github.com/knorrly/blakecoin-abe

forked from

Blakecoin-Abe: a free block chain browser for Bitcoin-based currencies.
https://github.com/bitcoin-abe/bitcoin-abe

    Copyright(C) 2011,2012,2013 by Abe developers.
    License: GNU Affero General Public License, see the file LICENSE.txt.
    Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.

Welcome to Abe!
===============

This software reads the Blakecoin block file, transforms and loads the
data into a database, and presents a web interface similar to Bitcoin
Block Explorer, http://blockexplorer.com/.

Abe draws inspiration from Bitcoin Block Explorer (BBE) and seeks some
level of compatibility with it but uses a completely new
implementation.

Installation
------------

Issue:

    python setup.py install

or simply run Abe from the directory containing setup.py.

Abe depends on Python 2.7 (or 2.6), the pycrypto package, and an SQL
database supporting ROLLBACK.  Abe runs on PostgreSQL, MySQL's InnoDB
engine, and SQLite.  Other SQL databases may work with minor changes.
Abe formerly ran on some ODBC configurations, Oracle, and IBM DB2, but
we have not tested to be sure it still works.  See the comments in
abe.conf about dbtype for configuration examples.

Abe works with files created by the original Blakecoin client.
You will need a copy of the block files (blk0001.dat, blk0002.dat,
etc. in your Blakecoin directory or its blocks/ subdirectory).  You may
let Abe read the block files while Blakecoin runs, assuming Blakecoin only
appends to the file.  Prior to Bitcoin v0.8, this assumption seemed
safe.  Abe may need some fixes to avoid skipping blocks while current
and future Blakecoin versions run.

License
-------

The GNU Affero General Public License (LICENSE.txt) requires whoever
modifies this code and runs it on a server to make the modified code
available to users of the server.  You may do this by forking the
Github project (if you received this code from Github.com), keeping
your modifications in the new project, and linking to it in the page
template.  Or you may wish to satisfy the requirement by simply
passing "--auto-agpl" to "python -m Abe.abe".  This option makes all
files in the directory containing abe.py and its subdirectories
available to clients.  See the comments in abe.conf for more
information.

Database
--------

For usage, run "python -m Abe.abe --help" and see the comments in
abe.conf.

You will have to specify a database driver and connection arguments
(dbtype and connect-args in abe.conf).  The dbtype is the name of a
Python module that supports your database.  Known to work are psycopg2
(for PostgreSQL) and sqlite3.  The value of connect-args depends on
your database configuration; consult the module's documentation of the
connect() method.

You may specify connect-args in any of the following forms:

* omit connect-args to call connect() with no arguments

* named arguments as a JSON object, e.g.:
  connect-args = { "database": "abe", "password": "b1tc0!n" }

* positional arguments as a JSON array, e.g.:
  connect-args = ["abe", "abe", "b1tc0!n"]

* a single string argument on one line, e.g.:
  connect-args = /var/lib/abe/abe.sqlite

For JSON syntax, see http://www.json.org.

Slow startup
------------

Reading the block files takes much too long, several days or more for
the main BTC block chain as of 2013.  However, if you use a persistent
database, Abe remembers where it stopped reading and starts more
quickly the second time.

Replacing the Block File
------------------------

Abe does not currently handle block file changes gracefully.  If you
replace your copy of the block chain, you must rebuild Abe's database
or (quicker) force a rescan.  To force a rescan of all data
directories, run Abe once with the "--rescan" option.

Web server
----------

By default, Abe expects to be run in a FastCGI environment.  For an
overview of FastCGI setup, see README-FASTCGI.txt.

To run the built-in HTTP server instead of FastCGI, specify a TCP port
and network interface in abe.conf, e.g.:

    port 2750
    host 127.0.0.1  # or a domain name

More information
----------------

Please see TODO.txt for a list of what is not yet implemented but
would like to be.

Abe Forum thread: https://bitcointalk.org/index.php?topic=22785.0
Newbies: https://bitcointalk.org/index.php?topic=51139.0
