#!/usr/bin/env python
# Copyright(C) 2011,2012,2013,2014 by Abe developers.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

"""Upgrade to the current database schema."""

import os
import sys
import DataStore
import util

def run_upgrades_locked(store, upgrades):
    for i in xrange(len(upgrades) - 1):
        vers, func = upgrades[i]
        if store.config['schema_version'] == vers:
            sv = upgrades[i+1][0]
            store.log.warning("Upgrading schema to version: %s", sv)
            func(store)
            if sv[:3] == 'Abe':
                store.sql(
                    "UPDATE configvar SET configvar_value = ?"
                    " WHERE configvar_name = 'schema_version'",
                    (sv,))
                if store.rowcount() != 1:
                    raise Exception("Failed to update schema_version");
            else:
                store.sql(
                    "UPDATE config SET schema_version = ? WHERE config_id = 1",
                    (sv,))
            store.commit()
            store.config['schema_version'] = sv

def run_upgrades(store, upgrades):
    """Guard against concurrent upgrades."""
    lock = store.get_lock()
    try:
        run_upgrades_locked(store, upgrades)
    finally:
        store.release_lock(lock)

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
    except Exception:
        store.rollback()
    store.sql("CREATE INDEX x_block_tx_tx ON block_tx (tx_id)")

def init_block_txin(store):
    store.log.info("Initializing block_txin.")
    count = int(store.selectrow("SELECT COUNT(1) FROM block_txin")[0] or 0)
    tried = 0
    added = 0
    seen = set()

    store.log.info("...loading existing keys")
    # XXX store.conn and store.sql_transform no longer exist.
    cur = store.conn.cursor()
    cur.execute(store.sql_transform("""
        SELECT block_id, txin_id FROM block_txin"""))
    for row in cur:
        seen.add(row)

    store.log.info("...finding output blocks")
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
                    store.log.info("commit %d", count)
        tried += 1
        if tried % 1000 == 0:
            sys.stdout.write('\r%d/%d ' % (added, tried))
            sys.stdout.flush()

    store.log.info('done.')

def init_block_value_in(store):
    store.log.info("Calculating block_value_in.")
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
    store.log.info("Calculating block_value_out.")
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
    store.log.info("Calculating block total generated and age.")
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
    store.log.info("Calculating satoshi-seconds destroyed.")
    count = 0
    step = 100
    start = 1
    stop = int(store.selectrow("SELECT MAX(block_id) FROM block_tx")[0])
    # XXX store.conn and store.sql_transform no longer exist.
    cur = store.conn.cursor()
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
             GROUP BY bt.block_id, bt.tx_id"""), (start, start + step))
        for row in cur:
            block_id, tx_id, destroyed = row
            sys.stdout.write("\rssd: " + str(count) + "   ")
            count += 1
            store.sql("UPDATE block_tx SET satoshi_seconds_destroyed = ?"
                      " WHERE block_id = ? AND tx_id = ?",
                      (destroyed, block_id, tx_id))
        start += step
    store.log.info("done.")

def set_0_satoshi_seconds_destroyed(store):
    store.log.info("Setting NULL to 0 in satoshi_seconds_destroyed.")
    # XXX store.conn and store.sql_transform no longer exist.
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

def init_block_satoshi_seconds(store, ):
    store.log.info("Calculating satoshi-seconds.")
    # XXX store.conn and store.sql_transform no longer exist.
    cur = store.conn.cursor()
    stats = {}
    cur.execute(store.sql_transform("""
        SELECT b.block_id, b.block_total_satoshis, b.block_nTime,
               b.prev_block_id, SUM(bt.satoshi_seconds_destroyed),
               b.block_height
          FROM block b
          JOIN block_tx bt ON (b.block_id = bt.block_id)
         GROUP BY b.block_id, b.block_total_satoshis, b.block_nTime,
               b.prev_block_id, b.block_height
         ORDER BY b.block_height"""))
    count = 0
    while True:
        row = cur.fetchone()
        if row is None:
            break
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
                   block_total_ss = ?,
                   block_ss_destroyed = ?
             WHERE block_id = ?""",
                  (store.intin(stats[block_id]['ss']),
                   store.intin(stats[block_id]['total_ss']),
                   store.intin(destroyed),
                   block_id))
        count += 1
        if count % 1000 == 0:
            store.commit()
            store.log.info("Updated %d blocks", count)
    if count % 1000 != 0:
        store.log.info("Updated %d blocks", count)

def index_block_nTime(store):
    store.log.info("Indexing block_nTime.")
    store.sql("CREATE INDEX x_block_nTime ON block (block_nTime)")

def replace_chain_summary(store):
    store.sql("DROP VIEW chain_summary")
    store.sql("""
        CREATE VIEW chain_summary AS SELECT
            cc.chain_id,
            cc.in_longest,
            b.block_id,
            b.block_hash,
            b.block_version,
            b.block_hashMerkleRoot,
            b.block_nTime,
            b.block_nBits,
            b.block_nNonce,
            cc.block_height,
            b.prev_block_id,
            prev.block_hash prev_block_hash,
            b.block_chain_work,
            b.block_num_tx,
            b.block_value_in,
            b.block_value_out,
            b.block_total_satoshis,
            b.block_total_seconds,
            b.block_satoshi_seconds,
            b.block_total_ss,
            b.block_ss_destroyed
        FROM chain_candidate cc
        JOIN block b ON (cc.block_id = b.block_id)
        LEFT JOIN block prev ON (b.prev_block_id = prev.block_id)""")

def drop_block_ss_columns(store):
    """Drop columns that may have been added in error."""
    for c in ['created', 'destroyed']:
        try:
            store.sql("ALTER TABLE block DROP COLUMN block_ss_" + c)
        except Exception:
            store.rollback()

def add_constraint(store, table, name, constraint):
    try:
        store.sql("ALTER TABLE " + table + " ADD CONSTRAINT " + name +
                  " " + constraint)
    except Exception:
        store.log.exception(
            "Failed to create constraint on table " + table + ": " +
            constraint + "; ignoring error.")
        store.rollback()

def add_fk_block_txin_block_id(store):
    add_constraint(store, "block_txin", "fk1_block_txin",
                   "FOREIGN KEY (block_id) REFERENCES block (block_id)")

def add_fk_block_txin_tx_id(store):
    add_constraint(store, "block_txin", "fk2_block_txin",
                   "FOREIGN KEY (txin_id) REFERENCES txin (txin_id)")

def add_fk_block_txin_out_block_id(store):
    add_constraint(store, "block_txin", "fk3_block_txin",
                   "FOREIGN KEY (out_block_id) REFERENCES block (block_id)")

def add_chk_block_txin_out_block_id_nn(store):
    add_constraint(store, "block_txin", "chk3_block_txin",
                   "CHECK (out_block_id IS NOT NULL)")

def create_x_cc_block_id(store):
    store.sql("CREATE INDEX x_cc_block_id ON chain_candidate (block_id)")

def reverse_binary_hashes(store):
    if store.config['binary_type'] != 'hex':
        raise Error(
            'To support search by hash prefix, we have to reverse all values'
            ' in block.block_hash, block.block_hashMerkleRoot, tx.tx_hash,'
            ' orphan_block.block_hashPrev, and unlinked_txin.txout_tx_hash.'
            ' This has not been automated. You may perform this step manually,'
            ' then issue "UPDATE config SET schema_version = \'9.1\'" and'
            ' rerun this program.')

def drop_x_cc_block_id(store):
    """Redundant with x_cc_block"""
    store.sql("DROP INDEX x_cc_block_id")

def create_x_cc_block_height(store):
    store.sql(
        "CREATE INDEX x_cc_block_height ON chain_candidate (block_height)")

def create_txout_approx(store):
    store.sql("""
        CREATE VIEW txout_approx AS SELECT
            txout_id,
            tx_id,
            txout_value txout_approx_value
          FROM txout""")

def add_fk_chain_candidate_block_id(store):
    add_constraint(store, "chain_candidate", "fk1_chain_candidate",
                   "FOREIGN KEY (block_id) REFERENCES block (block_id)")

def create_configvar(store):
    store.sql("""
        CREATE TABLE configvar (
            configvar_name  VARCHAR(100) NOT NULL PRIMARY KEY,
            configvar_value VARCHAR(255)
        )""")

def configure(store):
    # XXX This won't work anymore.
    store.args.binary_type = store.config['binary_type']
    store.configure()
    store.save_config()

def populate_abe_sequences(store):
    if store.config['sql.sequence_type'] == 'update':
        try:
            store.sql("""CREATE TABLE abe_sequences (
                             key VARCHAR(100) NOT NULL PRIMARY KEY,
                             nextid NUMERIC(30)
                         )""")
        except Exception:
            store.rollback()
        for t in ['block', 'tx', 'txin', 'txout', 'pubkey',
                  'chain', 'magic', 'policy']:
            (last_id,) = store.selectrow("SELECT MAX(" + t + "_id) FROM " + t)
            if last_id is None:
                continue
            store.sql("UPDATE abe_sequences SET nextid = ? WHERE key = ?"
                      " AND nextid <= ?",
                      (last_id + 1, t, last_id))
            if store.rowcount() < 1:
                store.sql("INSERT INTO abe_sequences (key, nextid)"
                          " VALUES (?, ?)", (t, last_id + 1))

def add_datadir_chain_id(store):
    store.sql("ALTER TABLE datadir ADD chain_id NUMERIC(10) NULL")

def noop(store):
    pass

def rescan_if_missed_blocks(store):
    """
    Due to a bug, some blocks may have been loaded but not placed in
    a chain.  If so, reset all datadir offsets to 0 to force a rescan.
    """
    (bad,) = store.selectrow("""
        SELECT COUNT(1)
          FROM block
          LEFT JOIN chain_candidate USING (block_id)
         WHERE chain_id IS NULL
    """)
    if bad > 0:
        store.sql(
            "UPDATE datadir SET blkfile_number = 1, blkfile_offset = 0")

def insert_missed_blocks(store):
    """
    Rescanning doesn't always work due to timeouts and resource
    constraints.  This may help.
    """
    missed = []
    for row in store.selectall("""
        SELECT b.block_id
          FROM block b
          LEFT JOIN chain_candidate cc ON (b.block_id = cc.block_id)
         WHERE chain_id IS NULL
         ORDER BY b.block_height
    """):
        missed.append(row[0])
    if not missed:
        return
    store.log.info("Attempting to repair %d missed blocks.", len(missed))
    inserted = 0
    for block_id in missed:
        # Insert block if its previous block is in the chain.
        # XXX This won't work if we want to support forks.
        # XXX This doesn't work for unattached blocks.
        store.sql("""
            INSERT INTO chain_candidate (
                chain_id, block_id, block_height, in_longest)
            SELECT cc.chain_id, b.block_id, b.block_height, 0
              FROM chain_candidate cc
              JOIN block prev ON (cc.block_id = prev.block_id)
              JOIN block b ON (b.prev_block_id = prev.block_id)
             WHERE b.block_id = ?""", (block_id,))
        inserted += store.rowcount()
        store.commit()  # XXX not sure why PostgreSQL needs this.
    store.log.info("Inserted %d rows into chain_candidate.", inserted)

def repair_missed_blocks(store):
    store.log.info("Finding longest chains.")
    best_work = []
    for row in store.selectall("""
        SELECT cc.chain_id, MAX(b.block_chain_work)
          FROM chain_candidate cc
          JOIN block b USING (block_id)
         GROUP BY cc.chain_id"""):
        best_work.append(row)
    best = []
    for row in best_work:
        chain_id, bcw = row
        (block_id,) = store.selectrow("""
            SELECT MIN(block_id)
              FROM block b
              JOIN chain_candidate cc USING (block_id)
             WHERE cc.chain_id = ?
               AND b.block_chain_work = ?
        """, (chain_id, bcw))
        (in_longest,) = store.selectrow("""
            SELECT in_longest
              FROM chain_candidate
             WHERE chain_id = ?
               AND block_id = ?
        """, (chain_id, block_id))
        if in_longest == 1:
            store.log.info("Chain %d already has the block of greatest work.",
                           chain_id)
            continue
        best.append([chain_id, block_id])
        store.sql("""
            UPDATE chain
               SET chain_last_block_id = ?
             WHERE chain_id = ?""",
                  (block_id, chain_id))
        if store.rowcount() == 1:
            store.log.info("Chain %d block %d", chain_id, block_id)
        else:
            raise Exception("Wrong rowcount updating chain " + str(chain_id))
    if not best:
        return
    store.log.info("Marking blocks in longest chains.")
    for elt in best:
        chain_id, block_id = elt
        count = 0
        while True:
            store.sql("""
                UPDATE chain_candidate
                   SET in_longest = 1
                 WHERE chain_id = ?
                   AND block_id = ?""",
                      (chain_id, block_id))
            if store.rowcount() != 1:
                raise Exception("Wrong rowcount updating chain_candidate ("
                                + str(chain_id) + ", " + str(block_id) + ")")
            count += 1
            row = store.selectrow("""
                SELECT b.prev_block_id, cc.in_longest
                  FROM block b
                  JOIN chain_candidate cc ON (b.prev_block_id = cc.block_id)
                 WHERE cc.chain_id = ?
                   AND b.block_id = ?""",
                                  (chain_id, block_id))
            if row is None:
                break  # genesis block?
            block_id, in_longest = row
            if in_longest == 1:
                break
        store.log.info("Processed %d in chain %d", count, chain_id)
    store.log.info("Repair successful.")

def add_block_num_tx(store):
    store.sql("ALTER TABLE block ADD block_num_tx NUMERIC(10)")

def add_block_ss_destroyed(store):
    store.sql("ALTER TABLE block ADD block_ss_destroyed NUMERIC(28)")

def init_block_tx_sums(store):
    store.log.info("Calculating block_num_tx and block_ss_destroyed.")
    rows = store.selectall("""
        SELECT block_id,
               COUNT(1),
               COUNT(satoshi_seconds_destroyed),
               SUM(satoshi_seconds_destroyed)
          FROM block
          JOIN block_tx USING (block_id)
         GROUP BY block_id""")
    count = 0
    store.log.info("Storing block_num_tx and block_ss_destroyed.")
    for row in rows:
        block_id, num_tx, num_ssd, ssd = row
        if num_ssd < num_tx:
            ssd = None
        store.sql("""
            UPDATE block
               SET block_num_tx = ?,
                   block_ss_destroyed = ?
             WHERE block_id = ?""",
                  (num_tx, ssd, block_id))
        count += 1
        if count % 1000 == 0:
            store.commit()
    # XXX would like to set NOT NULL on block_num_tx.

def config_ddl(store):
    # XXX This won't work anymore.
    store.configure_ddl_implicit_commit()
    store.save_configvar("ddl_implicit_commit")

def config_create_table_epilogue(store):
    # XXX This won't work anymore.
    store.configure_create_table_epilogue()
    store.save_configvar("create_table_epilogue")

def rename_abe_sequences_key(store):
    """Drop and recreate abe_sequences with key renamed to sequence_key."""
    # Renaming a column is horribly unportable.
    try:
        data = store.selectall("""
            SELECT DISTINCT key, nextid
              FROM abe_sequences""")
    except Exception:
        store.rollback()
        return
    store.log.info("copying sequence positions: %s", data)
    store.ddl("DROP TABLE abe_sequences")
    store.ddl("""CREATE TABLE abe_sequences (
        sequence_key VARCHAR(100) PRIMARY KEY,
        nextid NUMERIC(30)
    )""")
    for row in data:
        store.sql("INSERT INTO abe_sequences (sequence_key, nextid)"
                  " VALUES (?, ?)", row)

def create_x_txin_txout(store):
    store.sql("CREATE INDEX x_txin_txout ON txin (txout_id)")

def save_datadir(store):
    """Copy the datadir table to recreate it with a new column."""
    store.sql("CREATE TABLE abe_tmp_datadir AS SELECT * FROM datadir")

def add_datadir_id(store):
    data = store.selectall("""
        SELECT dirname, blkfile_number, blkfile_offset, chain_id
          FROM abe_tmp_datadir""")
    try:
        store.ddl("DROP TABLE datadir")
    except Exception:
        store.rollback()  # Assume already dropped.

    store.ddl("""CREATE TABLE datadir (
        datadir_id  NUMERIC(10) PRIMARY KEY,
        dirname     VARCHAR(2000) NOT NULL,
        blkfile_number NUMERIC(4) NULL,
        blkfile_offset NUMERIC(20) NULL,
        chain_id    NUMERIC(10) NULL
    )""")
    store.create_sequence("datadir")
    for row in data:
        new_row = [store.new_id("datadir")]
        new_row += row
        store.sql("""
            INSERT INTO datadir (
                datadir_id, dirname, blkfile_number, blkfile_offset, chain_id
            ) VALUES (?, ?, ?, ?, ?)""", new_row)

def drop_tmp_datadir(store):
    store.ddl("DROP TABLE abe_tmp_datadir")

def config_clob(store):
    # This won't work anymore.
    store.configure_max_varchar()
    store.save_configvar("max_varchar")
    store.configure_clob_type()
    store.save_configvar("clob_type")

def clear_bad_addresses(store):
    """Set address=Unknown for the bogus outputs in Bitcoin 71036."""
    bad_tx = [
        'a288fec5559c3f73fd3d93db8e8460562ebfe2fcf04a5114e8d0f2920a6270dc',
        '2a0597e665ac3d1cabeede95cedf907934db7f639e477b3c77b242140d8cf728',
        'e411dbebd2f7d64dafeef9b14b5c59ec60c36779d43f850e5e347abee1e1a455']
    for tx_hash in bad_tx:
        row = store.selectrow("""
            SELECT tx_id FROM tx WHERE tx_hash = ?""",
                              (store.hashin_hex(tx_hash),))
        if row:
            store.sql("""
                UPDATE txout SET pubkey_id = NULL
                 WHERE tx_id = ? AND txout_pos = 1 AND pubkey_id IS NOT NULL""",
                      (row[0],))
            if store.rowcount():
                store.log.info("Cleared txout %s", tx_hash)

def find_namecoin_addresses(store):
    updated = 0
    for tx_id, txout_pos, script in store.selectall("""
        SELECT tx_id, txout_pos, txout_scriptPubKey
          FROM txout
         WHERE pubkey_id IS NULL"""):
        pubkey_id = store.script_to_pubkey_id(store.binout(script))
        if pubkey_id is not None:
            store.sql("""
                UPDATE txout
                   SET pubkey_id = ?
                 WHERE tx_id = ?
                   AND txout_pos = ?""", (pubkey_id, tx_id, txout_pos))
            updated += 1
            if updated % 1000 == 0:
                store.commit()
                store.log.info("Found %d addresses", updated)
    if updated % 1000 > 0:
        store.commit()
        store.log.info("Found %d addresses", updated)

def create_abe_lock(store):
    store.ddl("""CREATE TABLE abe_lock (
        lock_id       NUMERIC(10) NOT NULL PRIMARY KEY,
        pid           VARCHAR(255) NULL
    )""")

def create_abe_lock_row(store):
    store.sql("INSERT INTO abe_lock (lock_id) VALUES (1)")

def insert_null_pubkey(store):
    dbnull = store.binin(DataStore.NULL_PUBKEY_HASH)
    row = store.selectrow("SELECT pubkey_id FROM pubkey WHERE pubkey_hash = ?",
                          (dbnull,))
    if row:
        # Null hash seen in a transaction.  Go to some trouble to
        # set its pubkey_id = 0 without violating constraints.
        old_id = row[0]
        import random  # No need for cryptographic strength here.
        temp_hash = "".join([chr(random.randint(0, 255)) for x in xrange(20)])
        store.sql("INSERT INTO pubkey (pubkey_id, pubkey_hash) VALUES (?, ?)",
                  (DataStore.NULL_PUBKEY_ID, store.binin(temp_hash)))
        store.sql("UPDATE txout SET pubkey_id = ? WHERE pubkey_id = ?",
                  (DataStore.NULL_PUBKEY_ID, old_id))
        store.sql("DELETE FROM pubkey WHERE pubkey_id = ?", (old_id,))
        store.sql("UPDATE pubkey SET pubkey_hash = ? WHERE pubkey_id = ?",
                  (dbnull, DataStore.NULL_PUBKEY_ID))
    else:
        store.sql("""
            INSERT INTO pubkey (pubkey_id, pubkey_hash) VALUES (?, ?)""",
                  (DataStore.NULL_PUBKEY_ID, dbnull))

def set_netfee_pubkey_id(store):
    store.log.info("Updating network fee output address to 'Destroyed'...")
    # XXX This doesn't work for Oracle because of LOB weirdness.
    # There, you could probably get away with:
    # UPDATE txout SET pubkey_id = 0 WHERE txout_scriptPubKey BETWEEN 1 AND 2;
    # UPDATE configvar SET configvar_value = 'Abe26' WHERE configvar_name =
    #     'schema_version' AND configvar_value = 'Abe25.3';
    # COMMIT;
    store.sql("""
        UPDATE txout
           SET pubkey_id = ?
         WHERE txout_scriptPubKey = ?""",
              (DataStore.NULL_PUBKEY_ID,
               store.binin(DataStore.SCRIPT_NETWORK_FEE)))
    store.log.info("...rows updated: %d", store.rowcount())

def adjust_block_total_satoshis(store):
    store.log.info("Adjusting value outstanding for lost coins.")
    block = {}
    block_ids = []

    store.log.info("...getting block relationships.")
    for block_id, prev_id in store.selectall("""
        SELECT block_id, prev_block_id
          FROM block
         WHERE block_height IS NOT NULL
         ORDER BY block_height"""):
        block[block_id] = {"prev_id": prev_id}
        block_ids.append(block_id)

    store.log.info("...getting lossage per block.")
    for block_id, lost in store.selectall("""
        SELECT block_tx.block_id, SUM(txout.txout_value)
          FROM block_tx
          JOIN txout ON (block_tx.tx_id = txout.tx_id)
         WHERE txout.pubkey_id <= 0
         GROUP BY block_tx.block_id"""):
        if block_id in block:
            block[block_id]["lost"] = lost

    store.log.info("...calculating adjustments.")
    for block_id in block_ids:
        b = block[block_id]
        prev_id = b["prev_id"]
        prev_lost = 0 if prev_id is None else block[prev_id]["cum_lost"]
        b["cum_lost"] = b.get("lost", 0) + prev_lost

    store.log.info("...applying adjustments.")
    count = 0
    for block_id in block_ids:
        adj = block[block_id]["cum_lost"]
        if adj != 0:
            store.sql("""
                UPDATE block
                  SET block_total_satoshis = block_total_satoshis - ?
                WHERE block_id = ?""",
                      (adj, block_id))
        count += 1
        if count % 1000 == 0:
            store.log.info("Adjusted %d of %d blocks.", count, len(block_ids))
    if count % 1000 != 0:
        store.log.info("Adjusted %d of %d blocks.", count, len(block_ids))

def config_concat_style(store):
    store._sql.configure_concat_style()
    store.config['sql.concat_style'] = store._sql.config['concat_style']
    store.save_configvar("sql.concat_style")

def config_limit_style(store):
    # XXX This won't work anymore.
    store.configure_limit_style()
    store.save_configvar("limit_style")

def config_sequence_type(store):
    # XXX This won't work anymore.
    if store.config['sequence_type'] != "update":
        return
    store.configure_sequence_type()
    if store.config['sequence_type'] != "update":
        store.log.info("Creating native sequences.")
        for name in ['magic', 'policy', 'chain', 'datadir',
                     'tx', 'txout', 'pubkey', 'txin', 'block']:
            store.get_db().drop_sequence_if_exists(name)
            store.create_sequence(name)
    store.save_configvar("sequence_type")

def add_search_block_id(store):
    store.log.info("Creating block.search_block_id")
    store.sql("ALTER TABLE block ADD search_block_id NUMERIC(14) NULL")

def populate_search_block_id(store):
    store.log.info("Calculating block.search_block_id")

    for block_id, height, prev_id in store.selectall("""
        SELECT block_id, block_height, prev_block_id
          FROM block
         WHERE block_height IS NOT NULL
         ORDER BY block_height"""):
        height = int(height)

        search_id = None
        if prev_id is not None:
            prev_id = int(prev_id)
            search_height = util.get_search_height(height)
            if search_height is not None:
                search_id = store.get_block_id_at_height(search_height, prev_id)
            store.sql("UPDATE block SET search_block_id = ? WHERE block_id = ?",
                      (search_id, block_id))
        store.cache_block(int(block_id), height, prev_id, search_id)
    store.commit()

def add_fk_search_block_id(store):
    add_constraint(store, "block", "fk1_search_block_id",
                   "FOREIGN KEY (search_block_id) REFERENCES block (block_id)")

def create_firstbits(store):
    flag = store.config.get('use_firstbits')

    if flag is None:
        if store.args.use_firstbits is None:
            store.log.info("use_firstbits not found, defaulting to false.")
            store.config['use_firstbits'] = "false"
            store.save_configvar("use_firstbits")
            return
        flag = "true" if store.args.use_firstbits else "false"
        store.config['use_firstbits'] = flag
        store.save_configvar("use_firstbits")

    if flag == "true":
        import firstbits
        firstbits.create_firstbits(store)

def populate_firstbits(store):
    if store.config['use_firstbits'] == "true":
        import firstbits
        firstbits.populate_firstbits(store)

def add_keep_scriptsig(store):
    store.config['keep_scriptsig'] = "true"
    store.save_configvar("keep_scriptsig")

def drop_satoshi_seconds_destroyed(store):
    store.get_db().drop_column_if_exists("block_txin", "satoshi_seconds_destroyed")

def widen_blkfile_number(store):
    data = store.selectall("""
        SELECT datadir_id, dirname, blkfile_number, blkfile_offset, chain_id
          FROM abe_tmp_datadir""")
    store.get_db().drop_table_if_exists("datadir")

    store.ddl("""CREATE TABLE datadir (
        datadir_id  NUMERIC(10) NOT NULL PRIMARY KEY,
        dirname     VARCHAR(2000) NOT NULL,
        blkfile_number NUMERIC(8) NULL,
        blkfile_offset NUMERIC(20) NULL,
        chain_id    NUMERIC(10) NULL
    )""")
    for row in data:
        store.sql("""
            INSERT INTO datadir (
                datadir_id, dirname, blkfile_number, blkfile_offset, chain_id
            ) VALUES (?, ?, ?, ?, ?)""", row)

def add_datadir_loader(store):
    store.sql("ALTER TABLE datadir ADD datadir_loader VARCHAR(100) NULL")

def add_chain_policy(store):
    store.ddl("ALTER TABLE chain ADD chain_policy VARCHAR(255)")

def populate_chain_policy(store):
    store.sql("UPDATE chain SET chain_policy = chain_name")

def add_chain_magic(store):
    store.ddl("ALTER TABLE chain ADD chain_magic BINARY(4)")

def populate_chain_magic(store):
    for chain_id, magic in store.selectall("""
        SELECT chain.chain_id, magic.magic
          FROM chain
          JOIN magic ON (chain.magic_id = magic.magic_id)"""):
        store.sql("UPDATE chain SET chain_magic = ? WHERE chain_id = ?",
                  (magic, chain_id))

def drop_policy(store):
    for stmt in [
        "ALTER TABLE chain DROP COLUMN policy_id",
        "DROP TABLE policy"]:
        try:
            store.ddl(stmt)
        except store.dbmodule.DatabaseError, e:
            store.log.warning("Cleanup failed, ignoring: %s", stmt)

def drop_magic(store):
    for stmt in [
        "ALTER TABLE chain DROP COLUMN magic_id",
        "DROP TABLE magic"]:
        try:
            store.ddl(stmt)
        except store.dbmodule.DatabaseError, e:
            store.log.warning("Cleanup failed, ignoring: %s", stmt)

def add_chain_decimals(store):
    store.ddl("ALTER TABLE chain ADD chain_decimals NUMERIC(2)")

def insert_chain_novacoin(store):
    import Chain
    try:
        store.insert_chain(Chain.create("NovaCoin"))
    except Exception:
        pass

def txin_detail_multisig(store):
    store.get_db().drop_view_if_exists('txin_detail')
    store.ddl("""
        CREATE VIEW txin_detail AS SELECT
            cc.chain_id,
            cc.in_longest,
            cc.block_id,
            b.block_hash,
            b.block_height,
            block_tx.tx_pos,
            tx.tx_id,
            tx.tx_hash,
            tx.tx_lockTime,
            tx.tx_version,
            tx.tx_size,
            txin.txin_id,
            txin.txin_pos,
            txin.txout_id prevout_id""" + (""",
            txin.txin_scriptSig,
            txin.txin_sequence""" if store.keep_scriptsig else """,
            NULL txin_scriptSig,
            NULL txin_sequence""") + """,
            prevout.txout_value txin_value,
            prevout.txout_scriptPubKey txin_scriptPubKey,
            pubkey.pubkey_id,
            pubkey.pubkey_hash,
            pubkey.pubkey
          FROM chain_candidate cc
          JOIN block b ON (cc.block_id = b.block_id)
          JOIN block_tx ON (b.block_id = block_tx.block_id)
          JOIN tx    ON (tx.tx_id = block_tx.tx_id)
          JOIN txin  ON (tx.tx_id = txin.tx_id)
          LEFT JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
          LEFT JOIN pubkey
              ON (prevout.pubkey_id = pubkey.pubkey_id)""")

def add_chain_script_addr_vers(store):
    store.ddl("ALTER TABLE chain ADD chain_script_addr_vers VARBINARY(100) NULL")

def populate_chain_script_addr_vers(store):
    def update(addr_vers, script_vers):
        store.sql("UPDATE chain SET chain_script_addr_vers=? WHERE chain_address_version=?",
                  (store.binin(script_vers), store.binin(addr_vers)))
    update('\x00', '\x05')
    update('\x6f', '\xc4')

def create_multisig_pubkey(store):
    store.ddl("""
        CREATE TABLE multisig_pubkey (
            multisig_id   NUMERIC(26) NOT NULL,
            pubkey_id     NUMERIC(26) NOT NULL,
            PRIMARY KEY (multisig_id, pubkey_id),
            FOREIGN KEY (multisig_id) REFERENCES pubkey (pubkey_id),
            FOREIGN KEY (pubkey_id) REFERENCES pubkey (pubkey_id)
        )""")

def create_x_multisig_pubkey_multisig(store):
    store.ddl("CREATE INDEX x_multisig_pubkey_pubkey ON multisig_pubkey (pubkey_id)")

def update_chain_policy(store):
    store.sql("""
        UPDATE chain
           SET chain_policy = 'Sha256Chain'
         WHERE chain_policy = chain_name
           AND chain_name IN ('Weeds', 'BeerTokens', 'SolidCoin', 'ScTestnet', 'Worldcoin', 'Anoncoin')""")

def populate_multisig_pubkey(store):
    store.init_chains()
    store.log.info("Finding new address types.")

    rows = store.selectall("""
        SELECT txout_id, chain_id, txout_scriptPubKey
          FROM txout_detail
         WHERE pubkey_id IS NULL""")

    count = 0
    for txout_id, chain_id, db_script in rows:
        script = store.binout(db_script)
        pubkey_id = store.script_to_pubkey_id(store.get_chain_by_id(chain_id), script)
        if pubkey_id > 0:
            store.sql("UPDATE txout SET pubkey_id = ? WHERE txout_id = ?",
                      (pubkey_id, txout_id))
            count += 1
    store.commit()
    store.log.info("Found %d", count)

sql_arg_names = (
    'binary_type', 'max_varchar', 'ddl_implicit_commit',
    'create_table_epilogue', 'sequence_type', 'limit_style',
    'int_type', 'clob_type')

def abstract_sql(store):
    for name in sql_arg_names:
        store.sql("""
            UPDATE configvar
               SET configvar_name = ?
             WHERE configvar_name = ?""", ('sql.' + name, name))
    store.commit()

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
    ('6.19', noop),
    ('6.20', index_block_nTime),
    ('6.21', replace_chain_summary),
    ('7',    replace_chain_summary),
    ('7.1',  index_block_tx_tx),  # forgot to put in abe.py
    ('7.2',  init_block_txin),    # abe.py put bad data there.
    ('7.3',  init_satoshi_seconds_destroyed),
    ('7.4',  set_0_satoshi_seconds_destroyed),
    ('7.5',  noop),
    ('7.6',  drop_block_ss_columns),
    ('8',    add_fk_block_txin_block_id),
    ('8.1',  add_fk_block_txin_tx_id),
    ('8.2',  add_fk_block_txin_out_block_id),
    ('8.3',  add_chk_block_txin_out_block_id_nn),
    ('8.4',  create_x_cc_block_id),
    ('9',    reverse_binary_hashes),
    ('9.1',  drop_x_cc_block_id),
    ('9.2',  create_x_cc_block_height),
    ('10',   create_txout_approx),
    ('11',   add_fk_chain_candidate_block_id),
    ('12',   create_configvar),
    ('12.1', configure),
    ('Abe13', populate_abe_sequences),
    ('Abe14', add_datadir_chain_id),
    ('Abe15', noop),
    ('Abe16', rescan_if_missed_blocks),  # May be slow.
    ('Abe17',   insert_missed_blocks),
    ('Abe17.1', repair_missed_blocks),
    ('Abe18',   add_block_num_tx),       # Seconds
    ('Abe18.1', add_block_ss_destroyed), # Seconds
    ('Abe18.2', init_block_tx_sums),     # 5 minutes
    ('Abe18.3', replace_chain_summary),  # Fast
    ('Abe19',   config_ddl),             # Fast
    ('Abe20',   config_create_table_epilogue), # Fast
    ('Abe20.1', rename_abe_sequences_key), # Fast
    ('Abe21',   create_x_txin_txout),    # 25 seconds
    ('Abe22',   save_datadir),           # Fast
    ('Abe22.1', add_datadir_id),         # Fast
    ('Abe22.2', drop_tmp_datadir),       # Fast
    ('Abe23',   config_clob),            # Fast
    ('Abe24',   clear_bad_addresses),    # Fast
    ('Abe24.1', find_namecoin_addresses), # 2 minutes if you have Namecoin
    ('Abe25',   create_abe_lock),        # Fast
    ('Abe25.1', create_abe_lock_row),    # Fast
    ('Abe25.2', insert_null_pubkey),     # 1 second
    ('Abe25.3', set_netfee_pubkey_id),   # Seconds
    ('Abe26',   adjust_block_total_satoshis), # 1-3 minutes
    ('Abe26.1', init_block_satoshi_seconds), # 3-10 minutes
    ('Abe27',   config_limit_style),     # Fast
    ('Abe28',   config_sequence_type),   # Fast
    # Should be okay back to here.
    ('Abe29',   add_search_block_id),    # Seconds
    ('Abe29.1', populate_search_block_id), # 1-2 minutes if using firstbits
    ('Abe29.2', add_fk_search_block_id), # Seconds
    ('Abe29.3', create_firstbits),       # Fast
    ('Abe29.4', populate_firstbits),     # Slow if config use_firstbits=true
    ('Abe30',   add_keep_scriptsig),     # Fast
    ('Abe31',   drop_satoshi_seconds_destroyed), # Seconds
    ('Abe32',   save_datadir),           # Fast
    ('Abe32.1', widen_blkfile_number),   # Fast
    ('Abe32.2', drop_tmp_datadir),       # Fast
    ('Abe33',   add_datadir_loader),     # Fast
    ('Abe34',   noop),                   # Fast
    ('Abe35',   add_chain_policy),       # Fast
    ('Abe35.1', populate_chain_policy),  # Fast
    ('Abe35.2', add_chain_magic),        # Fast
    ('Abe35.3', populate_chain_magic),   # Fast
    ('Abe35.4', drop_policy),            # Fast
    ('Abe35.5', drop_magic),             # Fast
    ('Abe36',   add_chain_decimals),     # Fast
    ('Abe36.1', insert_chain_novacoin),  # Fast
    ('Abe37',   txin_detail_multisig),   # Fast
    ('Abe37.1', add_chain_script_addr_vers), # Fast
    ('Abe37.2', populate_chain_script_addr_vers), # Fast
    ('Abe37.3', create_multisig_pubkey), # Fast
    ('Abe37.4', create_x_multisig_pubkey_multisig), # Fast
    ('Abe37.5', update_chain_policy),    # Fast
    ('Abe37.6', populate_multisig_pubkey), # Minutes-hours
    ('Abe38',   abstract_sql),           # Fast
    ('Abe39',   config_concat_style),    # Fast
    ('Abe40', None)
]

def upgrade_schema(store):
    if 'sql.binary_type' not in store.config:
        for name in sql_arg_names:
            store.config['sql.' + name] = store.config[name]
            del store.config[name]
        store.init_sql()

    run_upgrades(store, upgrades)
    sv = store.config['schema_version']
    curr = upgrades[-1][0]
    if sv != curr:
        raise Exception('Can not upgrade from schema version %s to %s\n'
                        % (sv, curr))
    store.log.warning("Upgrade complete.")

if __name__ == '__main__':
    print "Run Abe with --upgrade added to the usual arguments."
    sys.exit(2)
