Abe: a free block chain browser for Bitcoin-based currencies.
https://github.com/bitcoin-abe/bitcoin-abe

    Copyright(C) 2011,2012,2013 by Abe developers.
    Dockerfile + run.sh + other code contributed by Someguy123 @ Privex ( https://www.privex.io )
    License: GNU Affero General Public License, see the file LICENSE.txt.
    Portions Copyright (c) 2010 Gavin Andresen, see bct-LICENSE.txt.

Welcome to Abe!
===============

This software reads the Bitcoin block file, transforms and loads the
data into a database, and presents a web interface similar to Bitcoin
Block Explorer, http://blockexplorer.com/.

Abe draws inspiration from Bitcoin Block Explorer (BBE) and
BlockChain.info and seeks some level of compatibility with them but
uses a completely new implementation.

Docker Quickstart
-----------------

The easiest way to run an Abe explorer, is by using [Docker](https://www.docker.com/). Using the Abe Docker image allows you to
run Abe instantly - without installing python, installing system package dependencies, nor installing any python packages.
All you need is Docker.

If you don't yet have Docker - you can install it on Linux in one of these two ways:

```sh
# Option 1. - Auto-install for most major distros using Docker's quick install script:
curl -fsSL https://get.docker.com | sudo sh

# Option 2. - If the auto-install script isn't compatible with your distro, then you
# may be able to find Docker packaged by your distro, either as 'docker.io',
# or just 'docker'. Try running the appropriate package manager command for your
# distro below. If the package isn't found, try swapping 'docker' for 'docker.io'
# or vice versa.
apt install docker.io
dnf install docker
yum install docker
pacman -Sy docker
apk add docker
```

Once you have Docker installed, you can simply run @someguy123 's `someguy123/abe` docker image (you may need to be root),
and docker should automatically fetch the latest image from Docker Hub.

```sh
# Make a folder to store the general Abe data and configuration.
# By default, the Abe docker image uses SQLite for it's database, so the sqlite database
# file will be stored in your local host folder for the /app volume (e.g. ~/abe)
mkdir ~/abe

# Optionally, if you want to customise the Abe config (abe.conf), or the run.sh env vars,
# then you can generate a local config and/or env file, which will be automatically used,
# so long as they're in the local host folder for the container's /app volume
docker run --rm -it someguy123/abe dumpenv | tee ~/abe/.env
docker run --rm -it someguy123/abe dumpconf | tee ~/abe/abe.conf

# Check the help to see available subcommands and arguments. Be aware that arguments (flags/switches)
# must be placed BEFORE the subcommand to work. e.g. '-p 8586 serve' - where-as this won't work: 'serve -p 8586'
docker run --rm -it someguy123/abe help

# The first part of running Abe - is the block loader/indexer, which reads the blockchain files, extracts
# the block metadata + transactions, and puts them in the DB in a format the app can use.
# This command will run the loader as a background container - storing the DB / using config from ~/abe, 
# while reading the blockchain files from ~/.litecoin
docker run --rm --name abe-loader -v "${HOME}/abe:/app" -v "${HOME}/.litecoin:/blockchain" -itd someguy123/abe load

# The second part of running Abe - is the web server. The web server, as the name implies, serves the
# web application via a HTTP server. Just like with the loader, we mount the /app volume, but we don't
# have to mount the blockchain as the web server doesn't need it.
# By default, it will serve on port 8545, so we expose 8545 from the container to the internet (0.0.0.0),
# so that you can browse to your_server_ip:8545 and easily check that it works okay.
docker run --rm --name abe-web -v "${HOME}/abe:/app" -p '0.0.0.0:8545:8545' -it someguy123/abe serve

# Check the last 50 lines of the logs for the two containers to make sure they're working okay
docker logs -n 50 abe-loader
docker logs -n 50 abe-web

# In production, it's recommended to run multiple instances of the web server, each on a different port,
# so that requests can be distributed between each server process (using nginx/caddy or another 
# production web server), helping both performance, and reliability.
# Use '-p PORT' after '-it someguy123/abe' - which will be passed to run.sh inside of the container,
# instead of to docker.
docker run --rm --name abe-web2 -v "${HOME}/abe:/app" -p '0.0.0.0:8546:8546' -it someguy123/abe -p 8546 serve
```


Installation
------------

Install Dependencies:

    apt-get install -qy git wget curl libssl-dev libgirepository1.0-dev gobject-introspection cairo-5c libcairo-gobject2 libcairo2-dev pkg-config
    # The below packages are optional - but recommended. They're required to install the psycopg2 Python package
    # for using PostgreSQL as the database backend.
    apt-get install -qy libpq-dev postgresql-client-common postgresql-common
    apt-get clean -qy

Issue:

    # On older distros you may need to run just 'pip' instead of 'pip2'
    pip2 install cryptography pycryptodome
    # NOTE: The psycopg2 package (for using postgres) is included in the requirements.txt,
    # but it's optional. So if you don't plan to use psycopg2, you can ignore any errors
    # related to that package.
    pip2 install -r requirements.txt
    
    # On older distros, you may need to run 'python' instead of 'python2.7'
    python2.7 setup.py install

This will install abe to your system. After you set up the config file and
database (see below and README-<DB>.txt) you can run:

    python2.7 -m Abe.abe --config myconf.conf --commit-bytes 100000 --no-serve
    
This will perform the initial data load and will take a long time.
After it's fully synced, you can run the web server with: 

    python2.7 -m Abe.abe --config myconf.conf
    
To really get everything right see the README file for your type of
database.

Abe depends on Python 2.7 (or 2.6), the pycrypto package, and an SQL
database supporting ROLLBACK.  Abe runs on PostgreSQL, MySQL's InnoDB
engine, and SQLite.  Other SQL databases may work with minor changes.
Abe formerly ran on some ODBC configurations, Oracle, and IBM DB2, but
we have not tested to be sure it still works.  See the comments in
abe.conf about dbtype for configuration examples.

Abe works with files created by the original (Satoshi) Bitcoin client.
You will need a copy of the block files (blk0001.dat, blk0002.dat,
etc. in your Bitcoin directory or its blocks/ subdirectory).  You may
let Abe read the block files while Bitcoin runs, assuming Bitcoin only
appends to the file.  Prior to Bitcoin v0.8, this assumption seemed
safe.  Abe may need some fixes to avoid skipping blocks while current
and future Bitcoin versions run.

NovaCoin and CryptoCash support depends on the ltc_scrypt module
available from https://github.com/CryptoManiac/bitcoin-abe (see
README-SCRYPT.txt).

Hirocoin (and any other X11) support depends on the xcoin_hash module
available from https://github.com/evan82/xcoin-hash.

Bitleu (a Scrypt-Jane coin) depends on the yac_scrypt module.

Copperlark (a Keccak coin) depends on the sha3 module available via
"easy_install pysha3".

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

Input
-----

To display Namecoin, NovaCoin, or any block chain with data somewhere
other than the default Bitcoin directory, specify "datadir" in
abe.conf, e.g.:

    datadir = /home/bitcoin/.namecoin

The datadir directive can include a new chain's basic configuration,
e.g.:

    datadir += [{
            "dirname": "/home/weeds/testnet",
            "chain":   "Weeds",
            "code3":   "WDS",
            "address_version": "o" }]

Note that "+=" adds to the existing datadir configuration, while "="
replaces it.  For help with address_version, please open doc/FAQ.html
in a web browser.

The web interface is currently unaware of name transactions, but see
namecoin_dump.py in the tools directory.

More information
----------------

Please see TODO.txt for a list of what is not yet implemented but
would like to be.

Forum thread: https://bitcointalk.org/index.php?topic=22785.0
Newbies: https://bitcointalk.org/index.php?topic=51139.0

Donations appreciated: 1PWC7PNHL1SgvZaN7xEtygenKjWobWsCuf (BTC)
NJ3MSELK1cWnqUa6xhF2wUYAnz3RSrWXcK (NMC)
