Welcome to Abe!
===============

This software reads the Bitcoin block file, transforms and loads the
data into a database, and presents a web interface similar to Bitcoin
Block Explorer, <http://blockexplorer.com/>.

Abe draws inspiration from Bitcoin Block Explorer (BBE) and
BlockChain.info and seeks some level of compatibility with them but
uses a completely new implementation.

Installation
------------

Issue:

```bash
pipenv install
```

This will install abe to your virtual environment. After you set up the config
file and database (see below and `README-<DB>.txt`) you can run:

```bash
python -m Abe.abe --config myconf.conf --commit-bytes 100000 --no-serve
```

This will perform the initial data load and will take a long time.
After it's fully synced, you can run the web server with:

```bash
python -m Abe.abe --config myconf.conf
```

To really get everything right see the `README` file for your type of
database.

Abe depends on Python 3.8+, the `pycryptodome`, `flup-py3`, and `base58`
packages, and an SQL database supporting ROLLBACK.  Abe runs on PostgreSQL,
MySQL's InnoDB engine, and SQLite.  Other SQL databases may work with minor
changes. Abe formerly ran on some ODBC configurations, Oracle, and IBM DB2,
but we have not tested to be sure it still works.  See the comments in
[`abe.conf`](abe.conf) about dbtype for configuration examples.

Abe works with files created by the original (Satoshi) Bitcoin client.
You will need a copy of the block files (`blk0001.dat`, `blk0002.dat`,
etc. in your Bitcoin directory or its `blocks/` subdirectory).  You may
let Abe read the block files while Bitcoin runs, assuming Bitcoin only
appends to the file.  Prior to Bitcoin v0.8, this assumption seemed
safe.  Abe may need some fixes to avoid skipping blocks while current
and future Bitcoin versions run.

NovaCoin and CryptoCash support depends on the `ltc_scrypt` module
available from <https://github.com/CryptoManiac/bitcoin-abe> (see
[`README-SCRYPT.txt`](README-SCRYPT.txt)).

Hirocoin (and any other X11) support depends on the `xcoin_hash` module
available from <https://github.com/evan82/xcoin-hash>.

Bitleu (a Scrypt-Jane coin) depends on the `yac_scrypt` module.

Copperlark (a Keccak coin) depends on the sha3 module available via
`pipenv install pysha3`.

License
-------

The GNU Affero General Public License [`LICENSE.md`](LICENSE.md) requires
whoever modifies this code and runs it on a server to make the modified
code available to users of the server.  You may do this by forking the
Github project (if you received this code from <Github.com>), keeping
your modifications in the new project, and linking to it in the page
template.  Or you may wish to satisfy the requirement by simply
passing `--auto-agpl` to `python -m Abe.abe`.  This option makes all
files in the directory containing abe.py and its subdirectories
available to clients.  See the comments in [`abe.conf`](abe.conf) for
more information.

Database
--------

For usage, run `python -m Abe.abe --help` and see the comments in
[`abe.conf`](abe.conf).

You will have to specify a database driver and connection arguments
(`dbtype` and `connect-args` in [`abe.conf`](abe.conf)).  The `dbtype`
is the name of a Python module that supports your database.  Known to
work are `psycopg2` (for PostgreSQL), `mysqlclient` (for MySQL), and
`sqlite3`.  The value of connect-args depends on your database
configuration; consult the module's documentation of the `connect()`
method.

You may specify connect-args in any of the following forms:

* omit connect-args to call `connect()` with no arguments

* named arguments as a JSON object, e.g.:
  `connect-args = { "database": "abe", "password": "b1tc0!n" }`

* positional arguments as a JSON array, e.g.:
  `connect-args = ["abe", "abe", "b1tc0!n"]`

* a single string argument on one line, e.g.:
  `connect-args = /var/lib/abe/abe.sqlite`

For JSON syntax, see <http://www.json.org>.

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
directories, run Abe once with the `--rescan` option.

Web server
----------

By default, Abe expects to be run in a FastCGI environment.  For an
overview of FastCGI setup, see [`README-FASTCGI.txt`](README-FASTCGI.txt).

To run the built-in HTTP server instead of FastCGI, specify a TCP port
and network interface in [`abe.conf`](abe.conf), e.g.:

```config
    port 2750
    host 127.0.0.1  # or a domain name
```

Input
-----

To display Namecoin, NovaCoin, or any block chain with data somewhere
other than the default Bitcoin directory, specify `datadir` in
[`abe.conf`](abe.conf), e.g.:

```config
    datadir = /home/bitcoin/.namecoin
```

The `datadir` directive can include a new chain's basic configuration,
e.g.:

```config
    datadir += [{
            "dirname": "/home/weeds/testnet",
            "chain":   "Weeds",
            "code3":   "WDS",
            "address_version": "o" }]
```

Note that `+=` adds to the existing datadir configuration, while `=`
replaces it.  For help with address_version, please open the
[FAQ](doc/FAQ.html) in a web browser.

The web interface is currently unaware of name transactions, but see
`namecoin_dump.py` in the `tools` directory.

More information
----------------

Please see [`TODO.txt`](TODO.txt) for a list of what is not yet implemented but
would like to be.

Forum thread: <https://bitcointalk.org/index.php?topic=22785.0>
Newbies: <https://bitcointalk.org/index.php?topic=51139.0>

Donations appreciated: \
1PWC7PNHL1SgvZaN7xEtygenKjWobWsCuf (BTC) \
NJ3MSELK1cWnqUa6xhF2wUYAnz3RSrWXcK (NMC)

Abe: a free block chain browser for Bitcoin-based currencies.
<https://github.com/bitcoin-abe/bitcoin-abe>

_Copyright © 2011,2012,2013 by Abe developers._ \
_License: GNU Affero General Public License, see the file_ [`LICENSE.md`](LICENSE.md). \
_Portions Copyright (c) 2010 Gavin Andresen, see_ [`bct-LICENSE.txt`](bct-LICENSE.txt).

```hex
01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 3b a3 ed fd 7a 7b 12 b2 7a c7 2c 3e
67 76 8f 61 7f c8 1b c3 88 8a 51 32 3a 9f b8 aa
4b 1e 5e 4a 29 ab 5f 49 ff ff 00 1d 1d ac 2b 7c
01 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 ff ff ff ff 4d 04 ff ff 00 1d
01 04 45  T  h  e     T  i  m  e  s     0  3  /
 J  a  n  /  2  0  0  9     C  h  a  n  c  e  l
 l  o  r     o  n     b  r  i  n  k     o  f
 s  e  c  o  n  d     b  a  i  l  o  u  t     f
 o  r     b  a  n  k  s ff ff ff ff 01 00 f2 05
2a 01 00 00 00 43 41 04 67 8a fd b0 fe 55 48 27
19 67 f1 a6 71 30 b7 10 5c d6 a8 28 e0 39 09 a6
79 62 e0 ea 1f 61 de b6 49 f6 bc 3f 4c ef 38 c4
f3 55 04 e5 1e c1 12 de 5c 38 4d f7 ba 0b 8d 57
8a 4c 70 2b 6b f1 1d 5f ac 00 00 00 00
```
