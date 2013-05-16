Abe setup for MySQL: 8 easy steps.

1. Run the Bitcoin client once.  It'll create a .bitcoin directory in
your home directory, along with some other necessary files.

2. Install Python 2.7 and pycrypto.  The Debian/Ubuntu packages are
python2.7 and python-crypto. Also get python-MySQLDB. On Debian/Ubuntu: 
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
