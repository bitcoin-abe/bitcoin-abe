Abe setup for MySQL.

Run the Bitcoin client to ensure that your copy of the block chain is
up to date.

Install Python 2.7 and pycrypto.  The Debian/Ubuntu packages are
python2.7 and python-crypto.

Install MySQL 5.x server and MySQL-Python.  On Debian/Ubuntu:
mysql-server-5.1 and python-mysqldb.

Configure the MySQL instance with InnoDB engine support.  Often,
InnoDB is enabled by default.  To check for InnoDB support, issue
"SHOW ENGINES" and look in the output for "InnoDB" with "YES" next to
it.  If "skip-innodb" appears in the server configuration (my.cnf or
my.ini) then remove it and restart the server.

Log into MySQL as root (e.g.: mysql -u root) and issue the following,
replacing "PASSWORD" with a password you choose:

    create database abe;
    CREATE USER abe IDENTIFIED BY 'PASSWORD';
    grant all on abe.* to abe;

Create file abe-my.conf with the following contents, replacing
"PASSWORD" as above:

    dbtype MySQLdb
    connect-args {"user":"abe","db":"abe","passwd":"PASSWORD"}
    upgrade
    port 2750

Perform the initial data load:

    python -m Abe.abe --config abe-my.conf --commit-bytes 100000 --no-serve

Look for output such as:

    block_tx 1 1
    block_tx 2 2
    ...

This step may take several days depending on chain size and hardware.
Then run the web server as:

    python -m Abe.abe --config abe-my.conf

You should see:

    Listening on http://localhost:2750

Verify the installation by browsing the URL shown.
