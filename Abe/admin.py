#!/usr/bin/env python
# Copyright(C) 2012 by John Tobey <jtobey@john-edwin-tobey.org>

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

import DataStore
import readconf

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
    store.log.info("Updated %d txout_id.", store.cursor.rowcount)
    store.commit()

    store.sql("""
        DELETE FROM unlinked_txin
         WHERE (SELECT txout_id FROM txin
                 WHERE txin.txin_id = unlinked_txin.txin_id) IS NOT NULL""")
    store.log.info("Deleted %d unlinked_txin.", store.cursor.rowcount)
    store.commit()

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
    store.log.info("Deleted %d from unlinked_txin.", store.cursor.rowcount)

    store.sql("DELETE FROM txin WHERE tx_id = ?", (tx_id,))
    store.log.info("Deleted %d from txin.", store.cursor.rowcount)

    store.sql("DELETE FROM txout WHERE tx_id = ?", (tx_id,))
    store.log.info("Deleted %d from txout.", store.cursor.rowcount)

    store.sql("DELETE FROM tx WHERE tx_id = ?", (tx_id,))
    store.log.info("Deleted %d from tx.", store.cursor.rowcount)

    store.commit()
    store.log.info("Commit.")

def delete_block(store, id_or_hash):
    try:
        block_id = int(id_or_hash)
    except ValueError:
        (block_id,) = store.selectrow(
            "SELECT block_id FROM block WHERE block_hash = ?",
            (store.hashin_hex(id_or_hash),))
    store.log.info("Deleting block with block_id=%d", block_id)

    # XXX Need to handle descendant blocks.
    store.sql("DELETE FROM orphan_block WHERE block_id = ?", (block_id,))
    store.log.info("Deleted %d from orphan_block.", store.cursor.rowcount)

    store.sql("DELETE FROM block_txin WHERE block_id = ?", (block_id,))
    store.log.info("Deleted %d from block_txin.", store.cursor.rowcount)

def delete_chain_blocks(store, name):
    (chain_id,) = store.selectrow(
        "SELECT chain_id FROM chain WHERE chain_name = ?", (name,))
    block_ids = []
    for row in store.selectall(
        "SELECT block_id FROM chain_candidate WHERE chain_id = ?", (chain_id,)):
        block_ids.append(int(row[0]))
    store.log.info("Deleting %d blocks in chain %s", len(block_ids), name)

    store.sql("UPDATE chain SET chain_last_block_id = NULL WHERE chain_id = ?",
              (chain_id,))
    store.commit()
    store.log.info("Nulled chain_last_block_id.")

    store.sql("""
        DELETE FROM orphan_block WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    store.commit()
    store.log.info("Deleted %d from orphan_block.", store.cursor.rowcount)

    store.sql("""
        DELETE FROM block_next WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    store.commit()
    store.log.info("Deleted %d from block_next.", store.cursor.rowcount)

    store.sql("""
        UPDATE block
           SET prev_block_id = NULL,
               search_block_id = NULL,
               block_height = NULL
         WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    store.commit()
    store.log.info("Disconnected %d blocks from their parents.",
                   store.cursor.rowcount)

    store.sql("""
        DELETE FROM block_tx WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    store.commit()
    store.log.info("Deleted %d from block_tx.", store.cursor.rowcount)

    store.sql("""
        DELETE FROM block_txin WHERE block_id IN (
            SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                        (chain_id,))
    store.commit()
    store.log.info("Deleted %d from block_txin.", store.cursor.rowcount)

    if store.use_firstbits:
        store.sql("""
            DELETE FROM abe_firstbits WHERE block_id IN (
                SELECT block_id FROM chain_candidate WHERE chain_id = ?)""",
                            (chain_id,))
        store.commit()
        store.log.info("Deleted %d from abe_firstbits.", store.cursor.rowcount)

    store.sql("""
        DELETE FROM chain_candidate WHERE chain_id = ?""",
                        (chain_id,))
    store.commit()
    store.log.info("Deleted %d from chain_candidate.", store.cursor.rowcount)

    deleted = 0
    for block_id in block_ids:
        store.sql("DELETE FROM block WHERE block_id = ?", (block_id,))
        deleted += store.cursor.rowcount
    store.commit()
    store.log.info("Deleted %d from block.", deleted)

def main(argv):
    conf = {
        "debug":                    None,
        "logging":                  None,
        }
    conf.update(DataStore.CONFIG_DEFAULTS)

    args, argv = readconf.parse_argv(argv, conf,
                                     strict=False)
    if argv and argv[0] in ('-h', '--help'):
        print ("""Usage: python -m Abe.admin [-h] [--config=FILE] COMMAND...

Options:

  --help                    Show this help message and exit.
  --config FILE             Abe configuration file.

Commands:

  delete-chain-blocks NAME  Delete all blocks in the specified chain
                            from the database.

  delete-tx TX_ID           Delete the specified transaction.
  delete-tx TX_HASH

  link-txin                 Link transaction inputs to previous outputs.""")
        return 0

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(message)s")
    if args.logging is not None:
        import logging.config as logging_config
        logging_config.dictConfig(args.logging)

    store = DataStore.new(args)

    while len(argv) != 0:
        command = argv.pop(0)
        if command == 'delete-chain-blocks':
            delete_chain_blocks(store, argv.pop(0))
        #elif command == 'delete-block':
        #    delete_block(store, argv.pop(0))
        elif command == 'delete-tx':
            delete_tx(store, argv.pop(0))
        elif command == 'link-txin':
            link_txin(store)
        else:
            raise ValueError("Unknown command: " + command)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
