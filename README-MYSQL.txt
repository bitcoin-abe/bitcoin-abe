Abe setup example for MySQL.

On Debian/Ubuntu, install packages: mysql-server python-mysqldb

$ mysql -u root
mysql> create database abe;
mysql> CREATE USER abe IDENTIFIED BY 'Bitcoin';
mysql> grant all on abe.* to abe;
mysql>

$ cd bitcoin-abe
$ ./abe.py --dbtype MySQLdb --connect-args '{"user":"abe","host":"127.0.0.1","db":"abe","passwd":"Bitcoin"}' --port 2750 --upgrade
