PostgreSQL on Debian/Ubuntu.

Run the Bitcoin client to ensure that your copy of the block chain is
up to date.

Choose or create a system account to run Abe.  Replace USER with its
username throughout these instructions.

    apt-get install python2.7 python-crypto postgresql-8.4 python-psycopg2
    sudo -u postgres createdb abe
    sudo -u postgres createuser USER

Add the following line to /etc/postgresql/*/main/pg_hba.conf:

    local abe USER ident

Issue:

    sudo service postgresql reload

Create file abe-pg.conf with contents:

    dbtype psycopg2
    connect-args {"database":"abe"}
    upgrade
    port 2750

Perform the initial data load:

    python -m Abe.abe --config abe-pg.conf --commit-bytes 100000 --no-serve

Look for output such as:

    block_tx 1 1
    block_tx 2 2
    ...

This step may take several days depending on chain size and hardware.
Then run the web server as:

    python -m Abe.abe --config abe-pg.conf

You should see:

    Listening on http://localhost:2750

Verify the installation by browsing the URL shown.
