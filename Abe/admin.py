#!/usr/bin/env python
# Copyright(C) 2012,2013,2014 by Abe developers.

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

"""Delete a chain from the database, etc."""

import sys
import logging

import util

def commit(store):
    store.commit()
    store.log.info("Commit.")

def log_rowcount(store, msg):
    store.log.info(msg, store.rowcount())

def link_txin(store):
    store.log.info(
        "Linking missed transaction inputs to their previous outputs.")

    store.sql("""
        UPDATE txin SET txout_id = (
            SELECT txout_id
              FROM unlinked_txin JOIN txout JOIN tx ON (txout.tx_id = tx.tx_id)
             WHERE txin.txin_id = unlinked_txin.txin_id
               AND tx.tx_hash = unlinked_txin.txout_tx_hash
               AND txout.txout_pos = unlinked_txin.txout_pos)
         WHERE txout_id IS NULL""")
    log_rowcount(store, "Updated %d txout_id.")
    commit(store)

    store.sql("""
        DELETE FROM unlinked_txin
         WHERE (SELECT txout_id FROM txin
                 WHERE txin.txin_id = unlinked_txin.txin_id) IS NOT NULL""")
    log_rowcount(store, "Deleted %d unlinked_txin.")
    commit(store)

def delete_tx(store, id_or_hash):
    try:
        tx_id = int(id_or_hash)
    except ValueError:
        (tx_id,) = store.selectrow(
            "SELECT tx_id FROM tx WHERE tx_hash = ?",
            (store.hashin_hex(id_or_hash),))
    store.log.info("Deleting transaction with tx_id=%d", tx_id)

    store.sql("""
        DELETE FROM unlinked_txin WHERE txin_id IN (
            SELECT txin_id FROM txin WHERE tx_id = ?)""",
              (tx_id,))
    log_rowcount(store, "Deleted %d from unlinked_txin.")

    store.sql("DELETE FROM txin WHERE tx_id = ?", (tx_id,))
    log_rowcount(store, "Deleted %d from txin.")

    store.sql("DELETE FROM txout WHERE tx_id = ?", (tx_id,))
    log_rowcount(store, "Deleted %d from txout.")

    store.sql("DELETE FROM tx WHERE tx_id = ?", (tx_id,))
    log_rowcount(store, "Deleted %d from tx.")

    commit(store)

def rewind_datadir(store, dirname):
    store.sql("""
        UPDATE datadir
           SET blkfile_number = 1, blkfile_offset = 0
         WHERE dirname = ?
           AND (blkfile_number > 1 OR blkfile_offset > 0)""",
              (dirname,))
    log_rowcount(store, "Datadir blockfile pointers rewound: %d")
    commit(store)

def rewind_chain_blockfile(store, name, chain_id):
    store.sql("""
        UPDATE datadir
           SET blkfile_number = 1, blkfile_offset = 0
         WHERE chain_id = ?
           AND (blkfile_number > 1 OR blkfile_offset > 0)""",
              (chain_id,))
    log_rowcount(store, "Datadir blockfile pointers rewound: %d")

def chain_name_to_id(store, name):
    (chain_id,) = store.selectrow(
        "SELECT chain_id FROM chain WHERE chain_name = ?", (name,))
    return chain_id

def del_chain_blocks_1(store, name, chain_id):
    store.sql("UPDATE chain SET chain_last_block_id = NULL WHERE chain_id = ?",
              (chain_id,))
    store.log.info("Nulled %s chain_last_block_id.", name)

    store.sql("""
        UPDATE block
           SET prev_block_id = NULL,
               search_block_id = NULL
         WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    log_rowcount(store, "Disconnected %d blocks from chain.")
    commit(store)

    store.sql("""
        DELETE FROM orphan_block WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    log_rowcount(store, "Deleted %d from orphan_block.")
    commit(store)

    store.sql("""
        DELETE FROM block_next WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    log_rowcount(store, "Deleted %d from block_next.")
    commit(store)

    store.sql("""
        DELETE FROM block_txin WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    log_rowcount(store, "Deleted %d from block_txin.")
    commit(store)

    if store.use_firstbits:
        store.sql("""
            DELETE FROM abe_firstbits WHERE block_id IN (
                SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                            (chain_id,))
        log_rowcount(store, "Deleted %d from abe_firstbits.")
        commit(store)

def del_chain_block_tx(store, name, chain_id):
    store.sql("""
        DELETE FROM block_tx WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    log_rowcount(store, "Deleted %d from block_tx.")
    commit(store)

def delete_chain_blocks(store, name, chain_id = None):
    if chain_id is None:
        chain_id = chain_name_to_id(store, name)

    store.log.info("Deleting blocks in chain %s", name)
    del_chain_blocks_1(store, name, chain_id)
    del_chain_block_tx(store, name, chain_id)
    del_chain_blocks_2(store, name, chain_id)

def delete_chain_transactions(store, name, chain_id = None):
    if chain_id is None:
        chain_id = chain_name_to_id(store, name)

    store.log.info("Deleting transactions and blocks in chain %s", name)
    del_chain_blocks_1(store, name, chain_id)

    store.sql("""
        DELETE FROM unlinked_txin WHERE txin_id IN (
            SELECT txin.txin_id
              FROM chain_candidate cc
              JOIN block_tx bt ON (cc.block_id = bt.block_id)
              JOIN txin ON (bt.tx_id = txin.tx_id)
             WHERE cc.chain_id = ?)""", (chain_id,))
    log_rowcount(store, "Deleted %d from unlinked_txin.")

    store.sql("""
        DELETE FROM txin WHERE tx_id IN (
            SELECT bt.tx_id
              FROM chain_candidate cc
              JOIN block_tx bt ON (cc.block_id = bt.block_id)
             WHERE cc.chain_id = ?)""", (chain_id,))
    log_rowcount(store, "Deleted %d from txin.")
    commit(store)

    store.sql("""
        DELETE FROM txout WHERE tx_id IN (
            SELECT bt.tx_id
              FROM chain_candidate cc
              JOIN block_tx bt ON (cc.block_id = bt.block_id)
             WHERE cc.chain_id = ?)""", (chain_id,))
    log_rowcount(store, "Deleted %d from txout.")
    commit(store)

    tx_ids = []
    for row in store.selectall("""
        SELECT tx_id
          FROM chain_candidate cc
          JOIN block_tx bt ON (cc.block_id = bt.block_id)
         WHERE cc.chain_id = ?""", (chain_id,)):
        tx_ids.append(int(row[0]))

    del_chain_block_tx(store, name, chain_id)

    deleted = 0
    store.log.info("Deleting from tx...")

    for tx_id in tx_ids:
        store.sql("DELETE FROM tx WHERE tx_id = ?", (tx_id,))
        cnt = store.rowcount()

        if cnt > 0:
            deleted += 1
            if deleted % 10000 == 0:
                store.log.info("Deleting tx: %d", deleted)
                commit(store)

    store.log.info("Deleted %d from tx.", deleted)
    commit(store)

    del_chain_blocks_2(store, name, chain_id)

def del_chain_blocks_2(store, name, chain_id):
    block_ids = []
    for row in store.selectall(
        "SELECT block_id FROM chain_candidate WHERE chain_id = ?", (chain_id,)):
        block_ids.append(int(row[0]))

    store.sql("""
        DELETE FROM chain_candidate WHERE chain_id = ?""",
                        (chain_id,))
    log_rowcount(store, "Deleted %d from chain_candidate.")

    deleted = 0
    for block_id in block_ids:
        store.sql("DELETE FROM block WHERE block_id = ?", (block_id,))
        deleted += store.rowcount()
    store.log.info("Deleted %d from block.", deleted)

    rewind_chain_blockfile(store, name, chain_id)
    commit(store)

def main(argv):
    cmdline = util.CmdLine(argv)
    cmdline.usage = lambda: \
        """Usage: python -m Abe.admin [-h] [--config=FILE] COMMAND...

Options:

  --help                    Show this help message and exit.
  --config FILE             Abe configuration file.

Commands:

  delete-chain-blocks NAME  Delete all blocks in the specified chain
                            from the database.

  delete-chain-transactions NAME  Delete all blocks and transactions in
                            the specified chain.

  delete-tx TX_ID           Delete the specified transaction.
  delete-tx TX_HASH

  link-txin                 Link transaction inputs to previous outputs.

  rewind-datadir DIRNAME    Reset the pointer to force a rescan of
                            blockfiles in DIRNAME."""

    store, argv = cmdline.init()
    if store is None:
        return 0

    while len(argv) != 0:
        command = argv.pop(0)
        if command == 'delete-chain-blocks':
            delete_chain_blocks(store, argv.pop(0))
        elif command == 'delete-chain-transactions':
            delete_chain_transactions(store, argv.pop(0))
        elif command == 'delete-tx':
            delete_tx(store, argv.pop(0))
        elif command == 'rewind-datadir':
            rewind_datadir(store, argv.pop(0))
        elif command == 'link-txin':
            link_txin(store)
        else:
            raise ValueError("Unknown command: " + command)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
