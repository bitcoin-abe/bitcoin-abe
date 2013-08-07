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

def delete_chain(store, name):
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
                            from the database.""")
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
            delete_chain(store, argv.pop(0))
        else:
            raise ValueError("Unknown command: " + command)

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
