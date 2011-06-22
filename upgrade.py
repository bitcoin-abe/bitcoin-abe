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
    store.sql("CREATE INDEX x_block_tx_tx ON block_tx (tx_id)")

def init_block_txin(store):
    print "Initializing block_txin."

    print "...loading block_id chains"
    stats = {}
    for row in store.selectall("""
        SELECT cc.chain_id, cc.block_height, cc.in_longest,
               b.prev_block_id, b.block_id
          FROM chain_candidate cc
          JOIN block b USING (block_id)"""):
        (chain_id, height, in_longest, prev_id, block_id) = row

        if chain_id not in stats:
            stats[chain_id] = {}

        stats[chain_id][block_id] = {
            "in_longest": int(in_longest),
            "height": int(height),
            "prev_id": prev_id}

    print "...finding output blocks"
    ancestry = {}
    for row in store.selectall("""
        SELECT cc.chain_id, bt.block_id, txin.txin_id, obt.block_id
          FROM chain_candidate cc
          JOIN block_tx bt USING (block_id)
          JOIN txin USING (tx_id)
          JOIN txout USING (txout_id)
          JOIN block_tx obt ON (txout.tx_id = obt.tx_id)"""):
        (chain_id, block_id, txin_id, oblock_id) = row
        bstats = stats[chain_id][block_id]
        ostats = stats[chain_id][oblock_id]

        sys.stdout.write('\r' + str(chain_id) + ":" + str(block_id) + "  ")

        # If oblock is an ancestor of block, insert into block_txin.
        if bstats['in_longest']:
            if not ostats['in_longest']:
                continue
        elif block_id <> oblock_id:
            if not (block_id, oblock_id) in ancestry:
                id = bstats['prev_id']
                is_ancestor = False
                while (True):
                    print (str(block_id) + ": looking for output block "
                           + str(oblock_id) + ":" + str(id))
                    if id == oblock_id:
                        is_ancestor = True
                        break
                    if id is None:
                        break
                    s = stats[chain_id][id]
                    if s['in_longest']:
                        is_ancestor = (
                            ostats['in_longest'] and
                            ostats['height'] <= s['height'])
                        break
                    id = s['prev_id']

                ancestry[(block_id, oblock_id)] = is_ancestor

            if not ancestry[(block_id, oblock_id)]:
                continue
        store.sql("INSERT INTO block_txin (block_id, txin_id, out_block_id)"
                  " VALUES (?, ?, ?)",
                  (block_id, txin_id, oblock_id))

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
    cur.execute("""
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
         GROUP BY bt.block_id, bt.tx_id""")
    for row in cur:
        block_id, tx_id, destroyed = row
        sys.stdout.write("\rssd: " + str(count) + "   ")
        count += 1
        store.sql("UPDATE block_tx SET satoshi_seconds_destroyed = ?"
                  " WHERE block_id = ? AND tx_id = ?",
                  (destroyed, block_id, tx_id))
    print("done.")

def set_0_satoshi_seconds_destroyed(store):
    print "Setting NULL to 0 in satoshi_seconds_destroyed."
    cur = store.conn.cursor()
    cur.execute("""
        SELECT bt.block_id, bt.tx_id
          FROM block_tx bt
          JOIN block b USING (block_id)
         WHERE b.block_height IS NOT NULL
           AND bt.satoshi_seconds_destroyed IS NULL""")
    for row in cur:
        store.sql("""
            UPDATE block_tx bt SET satoshi_seconds_destroyed = 0
             WHERE block_id = ? AND tx_id = ?""", row)

def init_block_satoshi_seconds(store):
    print "Calculating satoshi-seconds."
    cur = store.conn.cursor()
    stats = {}
    cur.execute("""
        SELECT b.block_id, b.block_total_satoshis, b.block_nTime,
               b.prev_block_id, SUM(bt.satoshi_seconds_destroyed),
               b.block_height
          FROM block b
          JOIN block_tx bt USING (block_id)
         GROUP BY b.block_id, b.block_total_satoshis, b.block_nTime,
               b.prev_block_id, b.block_height
         ORDER BY b.block_height""")
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

def main(argv):
    args = abe.parse_argv(argv)  # XXX wrong help message.
    args.schema_version_check = False
    store = abe.DataStore(args)
    run_upgrades(store, [
                ('6', add_block_value_in),
                ('6.1', add_block_value_out),
                ('6.2', add_block_total_satoshis),
                ('6.3', add_block_total_seconds),
                ('6.4', add_block_satoshi_seconds),
                ('6.5', add_block_total_ss),
                ('6.6', add_satoshi_seconds_destroyed),
                ('6.7', add_cc_block_height),
                ('6.8', init_cc_block_height),
                ('6.9', index_cc_block_height),
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
                ('7', None)
                ])
    sv = store.config['schema_version']
    if sv != '7':
        sys.stderr.write('Can not upgrade from schema version ' + sv + '\n')
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
