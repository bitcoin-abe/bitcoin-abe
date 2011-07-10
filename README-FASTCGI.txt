Apache FastCGI setup, somewhat untested:

apt-get install libapache2-mod-fcgid

# /etc/apache2/sites-available/abe:
<VirtualHost *>
    ServerName YOUR.ABE.DOMAIN
    Alias /static/ /home/namecoin/src/bitcoin-abe/htdocs/
    Alias / /usr/lib/cgi-bin/abe.fcgi/
</VirtualHost>

ln -s ../sites-available/abe /etc/apache2/sites-enabled/
service apache2 reload

# Replace USER with your Unix user name:
# /usr/lib/cgi-bin/abe.fcgi:
#! /bin/sh
exec sudo -u USER /home/USER/cgi-bin/abe

chmod +x /usr/lib/cgi-bin/abe.fcgi

# Replace USER with your Unix user name and add to /etc/sudoers:
www-data ALL=(USER) NOPASSWD: /home/USER/cgi-bin/abe

mkdir -p /home/USER/cgi-bin

# /home/USER/cgi-bin/abe:
#! /bin/sh
PYTHONUNBUFFERED=1
export PYTHONUNBUFFERED
exec /home/USER/bitcoin-abe/abe.py --config /home/USER/abe.conf --static-path static/

chmod +x /home/USER/cgi-bin/abe
