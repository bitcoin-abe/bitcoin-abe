SQLite is not appropriate for a busy public service, since it does not
support concurrent access.

Ubuntu supplies the sqlite3 module in the python-pysqlite2 [sic]
package.

Create abe-sqlite.conf with contents:

    dbtype sqlite3
    connect-args abe.sqlite
    upgrade
    port 2750

Perform the initial data load:

    python -m Abe.abe --config abe-sqlite.conf --commit-bytes 100000 --no-serve

Look for output such as:

    block_tx 1 1
    block_tx 2 2
    ...

This step may take several days depending on chain size and hardware.
Then run the web server as:

    python -m Abe.abe --config abe-sqlite.conf

You should see:

    Listening on http://localhost:2750

Verify the installation by browsing the URL shown.
