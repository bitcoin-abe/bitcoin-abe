Apache 2 FastCGI setup on Debian/Ubuntu
=======================================

Install required packages:

    apt-get install apache2 libapache2-mod-fcgid python-flup
    apt-get install python-crypto

Replace YOUR.ABE.DOMAIN below with a domain that resolves to this
host.  The site will be http://YOUR.ABE.DOMAIN/.
Replace ABE/DIRECTORY/htdocs with the directory containing abe.css;
the Apache process must have permission to read it.
Replace "/usr/lib/cgi-bin" with another directory if you prefer;
Apache must have the directory configured with Options +ExecCGI.

Create file /etc/apache2/sites-available/abe with these contents:

    <VirtualHost *>
        ServerName YOUR.ABE.DOMAIN
        Alias /static/ ABE/DIRECTORY/htdocs/
        Alias / /usr/lib/cgi-bin/abe.fcgi/

        # Uncomment to log Abe requests.
        #ErrorLog /var/log/abe_error.log
        #LogLevel info
        #CustomLog /var/log/abe_access.log combined
    </VirtualHost>

Issue:

    a2ensite abe

Replace USER with your Unix user name and create file
/usr/lib/cgi-bin/abe.fcgi with these contents:

    #! /usr/bin/python
    import subprocess, sys, os
    command=["sudo", "-u", "USER", "/home/USER/cgi-bin/abe", str(os.getpid())]
    subprocess.Popen(command, stdin=sys.stdin).wait()

Make the file executable:

    chmod +x /usr/lib/cgi-bin/abe.fcgi

Replace USER with your Unix user name and use visudo(1) to append
the following to /etc/sudoers:
This allows the Apache account (www-data) to run Abe as USER.

    www-data ALL=(USER) NOPASSWD: /home/USER/cgi-bin/abe

Put configuration such as database connection parameters in
/home/USER/abe.conf or change the location below.  See the sample
abe.conf in the Abe distribution for file format.  IMPORTANT: Make
sure the configuration does NOT contain a "host" or "port" option.

Create file /home/USER/cgi-bin/abe with these contents:

    #! /bin/sh
    PYTHONUNBUFFERED=1 exec /home/USER/bitcoin-abe/abe.py \
    --config /home/USER/abe.conf --static-path static/ --watch-pid="$1"

Make the file executable:

    chmod +x /home/USER/cgi-bin/abe

Abe should be reachable at http://YOUR.ABE.DOMAIN/.
