#!/usr/bin/env python

"""Upgrade to the current database schema."""

import os
import sys
import abe

def add_block_value_in(store):
    store.sql("ALTER TABLE block ADD block_value_in NUMERIC(30)")
def add_block_value_out(store):
    store.sql("ALTER TABLE block ADD block_value_out NUMERIC(30)")
def add_block_total_satoshis(store):
    store.sql("ALTER TABLE block ADD block_total_satoshis NUMERIC(26)")
def add_block_total_seconds(store):
    store.sql("ALTER TABLE block ADD block_total_seconds NUMERIC(20)")
def add_block_satoshi_seconds(store):
    store.sql("ALTER TABLE block ADD block_satoshi_seconds NUMERIC(28)")
def add_block_total_ss(store):
    store.sql("ALTER TABLE block ADD block_total_ss NUMERIC(28)")
def add_satoshi_seconds_destroyed(store):
    store.sql("ALTER TABLE block_tx ADD satoshi_seconds_destroyed NUMERIC(28)")
def add_cc_block_height(store):
    store.sql("ALTER TABLE chain_candidate ADD block_height NUMERIC(14)")

def init_cc_block_height(store):
    store.sql(
"""UPDATE chain_candidate cc
    SET block_height = (
        SELECT block_height
          FROM block b
         WHERE b.block_id = cc.block_id)
""")

def index_cc_block_height(store):
    store.sql(
"""CREATE INDEX x_cc_chain_block_height
    ON chain_candidate (chain_id, block_height)""")

def index_cc_block(store):
    store.sql(
"""CREATE INDEX x_cc_block ON chain_candidate (block_id)""")

def create_block_txin(store):
    store.sql(
"""CREATE TABLE block_txin (
    block_id      NUMERIC(14),
    txin_id       NUMERIC(26),
    out_block_id  NUMERIC(14),
    PRIMARY KEY (block_id, txin_id)
)""")

def index_block_tx_tx(store):
    try:
        store.sql("DROP INDEX x_block_tx_tx")
    except:
        pass
    store.sql("CREATE INDEX x_block_tx_tx ON block_tx (tx_id)")

def init_block_txin(store):
    print "Initializing block_txin."
    count = int(store.selectrow("SELECT COUNT(1) FROM block_txin")[0] or 0)
    tried = 0
    added = 0
    seen = set()

    print "...loading existing keys"
    cur = store.conn.cursor()
    cur.execute(store.sql_transform("""
        SELECT block_id, txin_id FROM block_txin"""))
    for row in cur:
        seen.add(row)

    print "...finding output blocks"
    cur.execute(store.sql_transform("""
        SELECT bt.block_id, txin.txin_id, obt.block_id
          FROM block_tx bt
          JOIN txin USING (tx_id)
          JOIN txout USING (txout_id)
          JOIN block_tx obt ON (txout.tx_id = obt.tx_id)"""))
    for row in cur:
        (block_id, txin_id, oblock_id) = row

        if (block_id, txin_id) not in seen:
            # If oblock is an ancestor of block, insert into block_txin.
            if store.is_descended_from(block_id, oblock_id):
                store.sql("""
                    INSERT INTO block_txin (block_id, txin_id, out_block_id)
                    VALUES (?, ?, ?)""",
                          (block_id, txin_id, oblock_id))
                count += 1
                added += 1
                if count % 1000 == 0:
                    store.commit()
                    print "commit %d" % (count,)
        tried += 1
        if tried % 1000 == 0:
            sys.stdout.write('\r%d/%d ' % (added, tried))
            sys.stdout.flush()

    print('done.')

def init_block_value_in(store):
    print "Calculating block_value_in."
    for row in store.selectall("""
        SELECT b.block_id, SUM(txout.txout_value)
          FROM block b
          JOIN block_tx USING (block_id)
          JOIN txin USING (tx_id)
          LEFT JOIN txout USING (txout_id)
         GROUP BY b.block_id
    """):
        store.sql("UPDATE block SET block_value_in = ? WHERE block_id = ?",
                  (int(row[1] or 0), row[0]))

def init_block_value_out(store):
    print "Calculating block_value_out."
    for row in store.selectall("""
        SELECT b.block_id, SUM(txout.txout_value)
          FROM block b
          JOIN block_tx USING (block_id)
          JOIN txout USING (tx_id)
         GROUP BY b.block_id
    """):
        store.sql("UPDATE block SET block_value_out = ? WHERE block_id = ?",
                  (int(row[1]), row[0]))

def init_block_totals(store):
    print "Calculating block total generated and age."
    last_chain_id = None
    stats = None
    for row in store.selectall("""
        SELECT cc.chain_id, b.prev_block_id, b.block_id,
               b.block_value_out - b.block_value_in, b.block_nTime
          FROM chain_candidate cc
          JOIN block b USING (block_id)
         WHERE cc.block_height IS NOT NULL
         ORDER BY cc.chain_id, cc.block_height"""):

        chain_id, prev_id, block_id, generated, nTime = row
        generated = int(generated)
        nTime = int(nTime)

        if chain_id != last_chain_id:
            stats = {}
            last_chain_id = chain_id

        if prev_id is None:
            stats[block_id] = {
                "chain_start": nTime,
                "satoshis": generated}
        else:
            stats[block_id] = {
                "chain_start": stats[prev_id]['chain_start'],
                "satoshis": generated + stats[prev_id]['satoshis']}

        store.sql("UPDATE block SET block_total_seconds = ?,"
                  " block_total_satoshis = ?"
                  " WHERE block_id = ?",
                  (nTime - stats[block_id]['chain_start'],
                   stats[block_id]['satoshis'], block_id))

def init_satoshi_seconds_destroyed(store):
    print "Calculating satoshi-seconds destroyed."
    cur = store.conn.cursor()
    count = 0
    step = 100
    start = 1
    stop = int(store.selectrow("SELECT MAX(block_id) FROM block_tx")[0])
    while start <= stop:
        cur.execute(store.sql_transform("""
            SELECT bt.block_id, bt.tx_id,
                   SUM(txout.txout_value * (b.block_nTime - ob.block_nTime))
              FROM block b
              JOIN block_tx bt USING (block_id)
              JOIN txin USING (tx_id)
              JOIN txout USING (txout_id)
              JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
              JOIN block_txin bti ON (
                       bti.block_id = bt.block_id AND
                       bti.txin_id = txin.txin_id AND
                       obt.block_id = bti.out_block_id)
              JOIN block ob ON (bti.out_block_id = ob.block_id)
             WHERE bt.block_id >= ?
               AND bt.block_id < ?
             GROUP BY bt.block_id, bt.tx_id""", (start, start + step)))
        for row in cur:
            block_id, tx_id, destroyed = row
            sys.stdout.write("\rssd: " + str(count) + "   ")
            count += 1
            store.sql("UPDATE block_tx SET satoshi_seconds_destroyed = ?"
                      " WHERE block_id = ? AND tx_id = ?",
                      (destroyed, block_id, tx_id))
        start += step
    print("done.")

def set_0_satoshi_seconds_destroyed(store):
    print "Setting NULL to 0 in satoshi_seconds_destroyed."
    cur = store.conn.cursor()
    cur.execute(store.sql_transform("""
        SELECT bt.block_id, bt.tx_id
          FROM block_tx bt
          JOIN block b USING (block_id)
         WHERE b.block_height IS NOT NULL
           AND bt.satoshi_seconds_destroyed IS NULL"""))
    for row in cur:
        store.sql("""
            UPDATE block_tx bt SET satoshi_seconds_destroyed = 0
             WHERE block_id = ? AND tx_id = ?""", row)

def init_block_satoshi_seconds(store):
    print "Calculating satoshi-seconds."
    cur = store.conn.cursor()
    stats = {}
    cur.execute(store.sql_transform("""
        SELECT b.block_id, b.block_total_satoshis, b.block_nTime,
               b.prev_block_id, SUM(bt.satoshi_seconds_destroyed),
               b.block_height
          FROM block b
          JOIN block_tx bt USING (block_id)
         GROUP BY b.block_id, b.block_total_satoshis, b.block_nTime,
               b.prev_block_id, b.block_height
         ORDER BY b.block_height"""))
    for row in cur:
        block_id, satoshis, nTime, prev_id, destroyed, height = row
        satoshis = int(satoshis)
        destroyed = int(destroyed)
        if height is None:
            continue
        if prev_id is None:
            stats[block_id] = {
                "satoshis": satoshis,
                "ss": 0,
                "total_ss": 0,
                "nTime": nTime}
        else:
            created = (stats[prev_id]['satoshis']
                       * (nTime - stats[prev_id]['nTime']))
            stats[block_id] = {
                "satoshis": satoshis,
                "ss": stats[prev_id]['ss'] + created - destroyed,
                "total_ss": stats[prev_id]['total_ss'] + created,
                "nTime": nTime}
        store.sql("""
            UPDATE block
               SET block_satoshi_seconds = ?,
                   block_total_ss = ?
             WHERE block_id = ?""",
                  (stats[block_id]['ss'], stats[block_id]['total_ss'],
                   block_id))

def index_block_nTime(store):
    print "Indexing block_nTime."
    store.sql("CREATE INDEX x_block_nTime ON block (block_nTime)")

def replace_chain_summary(store):
    store.sql("DROP VIEW chain_summary")
    store.sql(store._view['chain_summary'])

def drop_block_ss_columns(store):
    """Drop columns that may have been added in error."""
    for c in ['created', 'destroyed']:
        try:
            store.sql("ALTER TABLE block DROP COLUMN block_ss_" + c)
        except:
            pass

def run_upgrades(store, upgrades):
    for i in xrange(len(upgrades) - 1):
        vers, func = upgrades[i]
        if store.config['schema_version'] == vers:
            func(store)
            sv = upgrades[i+1][0]
            store.sql(
                "UPDATE config SET schema_version = ? WHERE config_id = 1",
                (sv,))
            store.commit()
            store.config['schema_version'] = sv

upgrades = [
    ('6',    add_block_value_in),
    ('6.1',  add_block_value_out),
    ('6.2',  add_block_total_satoshis),
    ('6.3',  add_block_total_seconds),
    ('6.4',  add_block_satoshi_seconds),
    ('6.5',  add_block_total_ss),
    ('6.6',  add_satoshi_seconds_destroyed),
    ('6.7',  add_cc_block_height),
    ('6.8',  init_cc_block_height),
    ('6.9',  index_cc_block_height),
    ('6.10', index_cc_block),
    ('6.11', create_block_txin),
    ('6.12', index_block_tx_tx),
    ('6.13', init_block_txin),
    ('6.14', init_block_value_in),
    ('6.15', init_block_value_out),
    ('6.16', init_block_totals),
    ('6.17', init_satoshi_seconds_destroyed),
    ('6.18', set_0_satoshi_seconds_destroyed),
    ('6.19', init_block_satoshi_seconds),
    ('6.20', index_block_nTime),
    ('6.21', replace_chain_summary),
    ('7',    replace_chain_summary),
    ('7.1',  index_block_tx_tx),  # forgot to put in abe.py
    ('7.2',  init_block_txin),    # abe.py put bad data there.
    ('7.3',  init_satoshi_seconds_destroyed),
    ('7.4',  set_0_satoshi_seconds_destroyed),
    ('7.5',  init_block_satoshi_seconds),
    ('7.6',  drop_block_ss_columns),
    ('8', None)
]

def upgrade_schema(store):
    run_upgrades(store, upgrades)
    sv = store.config['schema_version']
    curr = upgrades[-1][0]
    if sv != curr:
        raise Exception('Can not upgrade from schema version %s to %s\n'
                        % (sv, curr))

if __name__ == '__main__':
    print "Run ./abe.py with --upgrade added to the usual arguments."
    sys.exit(2)
