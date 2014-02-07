Apache 2 FastCGI setup on Debian/Ubuntu
=======================================

This document describes how to install and run Abe as a FastCGI
process under Apache 2 on a Debian GNU/Linux or Ubuntu system.
Advantages of FastCGI over the built-in HTTP server include:

    * lets browsers cache static content for better performance;
    * can integrate with an existing website, no :2750 in URLs.

These instructions assume root privileges.  To begin a privileged
session in a terminal window, issue "sudo -i" (Ubuntu) or "su -"
(Debian).

Install required packages:

    apt-get install apache2 libapache2-mod-fcgid python-flup
    apt-get install python-crypto

Change directory to the Abe distribution and install Abe:

    cd bitcoin-abe
    python setup.py install

Replace YOUR.ABE.DOMAIN below with a domain that resolves to this
host.  The site will be http://YOUR.ABE.DOMAIN/.  To embed Abe in an
existing site (e.g., http://YOUR.DOMAIN/abe/) prepend a path (e.g.,
"/abe") in the Alias directives, place them in your existing
sites-available file instead of a new VirtualHost, and merge or create
your site's /robots.txt with adjusted paths from Abe/htdocs/robots.txt.

Replace HTDOCS/DIRECTORY below with the directory containing abe.css;
the Apache process must have permission to read it.  The following
command displays the correct value:

    python -m Abe.abe --print-htdocs-directory

Optionally, replace "/usr/lib/cgi-bin" below with another directory;
Apache must have the directory configured with Options +ExecCGI.

Create file /etc/apache2/sites-available/abe with these contents:

    <VirtualHost *:80>
        ServerName YOUR.ABE.DOMAIN
        Alias /static/ HTDOCS/DIRECTORY/
        Alias /robots.txt HTDOCS/DIRECTORY/robots.txt
        Alias /favicon.ico HTDOCS/DIRECTORY/favicon.ico
        Alias / /usr/lib/cgi-bin/abe.fcgi/

        # Raise this if you get server errors mentioning "mod_fcgid:
        # read data timeout in 40 seconds"
        #FcgidIOTimeout 40

        # Uncomment to log Abe requests.
        #ErrorLog /var/log/abe_error.log
        #LogLevel info
        #CustomLog /var/log/abe_access.log combined
    </VirtualHost>

Enable the new configuration:

    a2ensite abe
    service apache2 reload

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

    # This allows the Apache account (www-data) to run Abe as USER.
    www-data ALL=(USER) NOPASSWD: /home/USER/cgi-bin/abe

Put configuration such as database connection parameters in
/home/USER/abe.conf or change the location below.  See the sample
abe.conf in the Abe distribution for file format.  IMPORTANT: Make
sure the configuration does NOT contain a "host" or "port" option.

Create file /home/USER/cgi-bin/abe with these contents:

    #! /bin/sh
    PYTHONUNBUFFERED=1 exec python -m Abe.abe \
    --config /home/USER/abe.conf --static-path static/ --watch-pid="$1"

Make the file executable:

    chmod +x /home/USER/cgi-bin/abe

Abe should be reachable at http://YOUR.ABE.DOMAIN/.  Exit the
privileged session:

    exit
