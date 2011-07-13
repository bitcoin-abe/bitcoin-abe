PostgreSQL on Debian/Ubuntu:

apt-get install postgresql python-psycopg2
sudo -u postgres createdb abe
# Replace USER with your Unix user name:
sudo -u postgres createuser USER
# Replace 8.4 with the PostgreSQL version:
sudo sh -c "echo local abe USER ident >> /etc/postgresql/8.4/main/pg_hba.conf"
sudo service postgresql reload
