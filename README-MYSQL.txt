Abe setup for MySQL: 8 easy steps.

1. Run the Bitcoin client once.  It'll create a .bitcoin directory in
your home directory, along with some other necessary files.

2. Install Python 2.7 and pycrypto and python-mysqldb.  The Debian/Ubuntu packages 
are python2.7, python-crypto, and python-mysqldb. You can use PIP 
(python package manager) to get pycrypto; mysqldb requires (Debian/Ubuntu)
sudo apt-get install python-mysqldb

3. Install MySQL 5.x server and MySQL-Python.  On Debian/Ubuntu:
sudo apt-get install mysql-client mysql-server

4. Configure the MySQL instance with InnoDB engine support.  If you
installed with Debian/Ubuntu then InnoDB is enabled by default.  
To check for InnoDB support, issue "SHOW ENGINES" and look in the output
for "InnoDB" with "YES" next to it.  If "skip-innodb" appears in the server 
configuration (my.cnf or my.ini) then remove it and restart the server.

5. Log into MySQL as root (e.g.: mysql -u root) and issue the following,
replacing "PASSWORD" with a password you choose:

    create database abe;
    CREATE USER 'abe'@'localhost' IDENTIFIED BY 'PASSWORD';
    grant all on abe.* to abe;

6. Create file abe-my.conf with the following contents, replacing
"PASSWORD" as above:

    dbtype MySQLdb
    connect-args {"user":"abe","db":"abe","passwd":"PASSWORD"}
    upgrade
    port 2750

7. Perform the initial data load:

    python -m Abe.abe --config abe-my.conf --commit-bytes 100000 --no-serve

Look for output such as:

    block_tx 1 1
    block_tx 2 2
    ...

This step may take several days depending on chain size and hardware.

8. Then run the web server as:

    python -m Abe.abe --config abe-my.conf

You should see:

    Listening on http://localhost:2750

Verify the installation by browsing the URL shown.

APPENDIX A -- Using InnoDB Compressed Tables

If you're using InnoDB with innodb_file_format=Barracuda and
innodb_file_per_table=1, it is possible to save a great deal of space by
compressing InnoDB tables. Another benefit of compression is reduced IO which
can help when IO is the bottleneck.

Compression can be done at any time, however it is desirable to do it as
early as possible; it will take much longer to run on a fully populated
database. Also please note that you should not compress tables while Abe is
running.

The general command to compress a table is:

ALTER TABLE <table> ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=<n>;

Where <n> is one of 1, 2, 4, 8 or 16.

Without going into many details, the KEY_BLOCK_SIZE parameter affects both
compression ratio and performance, and longer rows requires larger sizes as
well. To save you the trouble, the following commands have been prepared to
give you the greatest compression ratio. (NB: For the bigger tables the
compression has been tested only on small subset of tables -- 1M rows.)

ALTER TABLE txin ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;
ALTER TABLE txout ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;
ALTER TABLE block_txin ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;
ALTER TABLE tx ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8;
ALTER TABLE block_tx ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;
ALTER TABLE pubkey ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8;
ALTER TABLE block ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4;
ALTER TABLE chain_candidate ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=2;
ALTER TABLE block_next ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=2;

These settings were tested on a MySQL database with binary-type=binary and
default settings for firstbits and scripsig. Compression of a full Abe
database reduced its size from 36G (37254132 KiB) down to only 17G
(17409008 KiB), a 53% compression ratio.

To test for yourself, the following bash code prints out SQL commands to
copy each table above into a compressed table for each key size. You can
add a "LIMIT <n>" at the end of the INSERT queries to set an upper limit on
copied rows.

for t in txin txout block_txin tx block_tx pubkey block chain_candidate block_next
do
    for l in 1 2 4 8 16
    do
        echo "CREATE TABLE ${t}_kbs$l like $t;"
        echo "ALTER TABLE ${t}_kbs$l KEY_BLOCK_SIZE=$l ROW_FORMAT=COMPRESSED;"
        echo "INSERT INTO ${t}_kbs$l SELECT * FROM $t;"
    done
done

Then compare the size of your table's .ibd files for each KEY_BLOCK_SIZE.

APPENDIX B: Using TokuDB

TokuDB is an optional engine for MySQL/MariaDB optimized for fast inserts.
Compared to Innodb, TokuDB has the following advantages:

- All tables compressed by default - compression ratio is higher then InnoDB
  without tuning.
- Faster inserts (mostly visible loading empty blocks; loading transaction
  requires linking txin's, and the lookup for those slows inserts, although it
  remains order of magnitude than InnoDB).
- Heavily reduced disk IO, excellent for slow disks, reduces contention with
  other loads like the Bitcoin Client.
- Extremely fast backup restoration (tested from a SQL dump - using LOAD DATA
  INFILE could be even faster!)

The drawbacks experienced were:

- TokuDB does *not* enforce foreign key check. There are small risks that bugs
  lead to inconsistent database and, more importantly, it will not guard you
  against accidentally breaking table relations when manually altering the
  database contents.
- During initial tests, TokuDB required running ANALYZE TABLE on all tables at
  least once to properly compute index cardinality. This is most important to
  run *during* the initial load or after restoring from backup to ensure
  optimal query optimisation.


You can load the full blockchain into a database whose default engine is
TokuDB (NB: Abe will add `ENGINE=InnoDB` *only* when the default engine does
not support transactions). To set the default engine at connect time, add the
following option to your MySQLdb connect-args:

    "init_command":"SET default_storage_engine='TokuDB'"

Ex. if your user and database name is abe, with no password, use:

    connect-args {"user":"abe","db":"abe","init_command":"SET default_storage_engine='TokuDB'"}


There are options to convert, however you should make sure to also set the
default engine as above to ensure any new tables created during upgrades uses
TokuDB.

You should be able to convert an existing database using (UNTESTED):
    ALTER TABLE `table` ENGINE=TokuDB;
(You may have to disable foreign key checks first)

Another option is to load a SQL backup while passing the file contents trough
sed:

    cat dump.sql |sed -r 's/ENGINE=InnoDB/ENGINE=TokuDB/;s/ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=[0-9]+//' | mysql <options>

For simplicity this example uses `cat`, but you should probably use
compression on the sql file to reduce IO.


TODO:

Some ideas on enhancements for TokuDB:

- Backup script using SELECT INTO OUTFILE / LOAD DATA INFILE (fatser)
- ANALYZE script
- Script to check FK relations?

