#!/usr/bin/env python

"""Upgrade to the current database schema."""

import os
import sys
# Find modules in parent directory.
sys.path.append(os.path.join(os.path.split(__file__)[0], '..'))
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

def init_block_satoshi_seconds(store):
    print "Calculating satoshi-seconds."
    last_chain_id = None
    chain_nTime = 0
    stats = None
    for row in store.selectall("""
        SELECT cc.chain_id, b.prev_block_id,
               b.block_id, b.block_nTime, b.block_value_in, b.block_value_out,
               SUM(ob.block_nTime * txout.txout_value)
          FROM chain_candidate cc
          JOIN block b USING (block_id)
          JOIN block_tx USING (block_id)
          JOIN txin USING (tx_id)
          LEFT JOIN txout USING (txout_id)
          LEFT JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
          LEFT JOIN block ob ON (obt.block_id = ob.block_id)
         WHERE b.block_height IS NOT NULL
         GROUP BY cc.chain_id, b.prev_block_id, b.block_height,
               b.block_id, b.block_nTime, b.block_value_in, b.block_value_out
         ORDER BY cc.chain_id, b.block_height
    """):
        chain_id, prev_id, block_id, nTime, value_in, value_out, tv_in = row
        nTime = int(nTime)
        value_in = int(value_in)
        value_out = int(value_out)
        tv_in = int(tv_in or 0)
        generation_fee = value_out - value_in

        if chain_id == last_chain_id:
            if prev_id is None:
                raise Error('Unattached block ' + block_id + ' has height')
            ostats = stats[prev_id]
            ss_created = ostats['satoshis'] * (nTime - ostats['nTime'])
            ss_destroyed = nTime * value_in - tv_in
            stats[block_id] = {
                "satoshis": ostats['satoshis'] + generation_fee,
                "ss": ostats['ss'] + ss_created - ss_destroyed,
                "nTime": nTime,
                }
        else:
            if prev_id is not None:
                raise Error('Can not find chain ' + chain_id + ' genesis block')
            chain_nTime = nTime
            stats = {block_id: {
                        "satoshis": generation_fee,
                        "ss": 0,
                        "nTime": nTime}}
            last_chain_id = chain_id

        store.sql("""
            UPDATE block
               SET block_total_satoshis = ?,
                   block_total_seconds = ?,
                   block_satoshi_seconds = ?
             WHERE block_id = ?""",
                  (stats[block_id]['satoshis'], nTime - chain_nTime,
                   stats[block_id]['ss'], block_id))

def index_block_nTime(store):
    print "Indexing block_nTime."
    store.sql("CREATE INDEX x_block_nTime ON block (block_nTime)")

def reload_chain_summary(store):
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
            ('6',   add_block_value_in),
            ('6.1', add_block_value_out),
            ('6.2', add_block_total_satoshis),
            ('6.3', add_block_total_seconds),
            ('6.4', add_block_satoshi_seconds),
            ('6.5', init_block_value_in),
            ('6.6', init_block_value_out),
            ('6.7', init_block_satoshi_seconds),
            ('6.8', index_block_nTime),
            ('6.9', reload_chain_summary),
            ('7', None)
            ])
    sv = store.config['schema_version']
    if sv != '7':
        sys.stderr.write('Can not upgrade from schema version ' + sv + '\n')
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
