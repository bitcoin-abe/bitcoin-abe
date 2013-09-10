#!/usr/bin/env python
# Copyright(C) 2011,2012 by Abe developers.

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

"""Reconfigure an Abe instance to use or not use Firstbits."""

def populate_firstbits(store):
    blocks, fbs = 0, 0
    log_incr = 1000

    for addr_vers, block_id in store.selectall("""
        SELECT c.chain_address_version,
               cc.block_id
          FROM chain c
          JOIN chain_candidate cc ON (c.chain_id = cc.chain_id)
         WHERE cc.block_height IS NOT NULL
         ORDER BY cc.chain_id, cc.block_height"""):
        fbs += store.do_vers_firstbits(addr_vers, int(block_id))
        blocks += 1
        if blocks % log_incr == 0:
            store.commit()
            store.log.info("%d firstbits in %d blocks" % (fbs, blocks))

    if blocks % log_incr > 0:
        store.commit()
        store.log.info("%d firstbits in %d blocks" % (fbs, blocks))

def create_firstbits(store):
    store.log.info("Creating firstbits table.")
    store.ddl(
        """CREATE TABLE abe_firstbits (
            pubkey_id       NUMERIC(26) NOT NULL,
            block_id        NUMERIC(14) NOT NULL,
            address_version BIT VARYING(80) NOT NULL,
            firstbits       VARCHAR(50) NOT NULL,
            PRIMARY KEY (address_version, pubkey_id, block_id),
            FOREIGN KEY (pubkey_id) REFERENCES pubkey (pubkey_id),
            FOREIGN KEY (block_id) REFERENCES block (block_id)
        )""")
    store.ddl(
        """CREATE INDEX x_abe_firstbits
            ON abe_firstbits (address_version, firstbits)""")

def drop_firstbits(store):
    store.log.info("Dropping firstbits table.")
    store.ddl("DROP TABLE abe_firstbits")

def reconfigure(store, args):
    have = store.config['use_firstbits'] == "true"
    want = args.use_firstbits
    if have == want:
        return
    lock = store.get_lock()
    try:
        # XXX Should temporarily store a new schema_version.
        if want:
            create_firstbits(store)
            populate_firstbits(store)
            store.config['use_firstbits'] = "true"
        else:
            drop_firstbits(store)
            store.config['use_firstbits'] = "false"

        store.use_firstbits = want
        store.save_configvar("use_firstbits")
        store.commit()

    finally:
        store.release_lock(lock)
