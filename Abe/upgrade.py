#!/usr/bin/env python
# Copyright(C) 2011,2012,2013 by John Tobey <jtobey@john-edwin-tobey.org>

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
                if store.cursor.rowcount != 1:
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

def noop(store):
    pass

def add_datadir_loader(store):
    store.sql("ALTER TABLE datadir ADD datadir_loader VARCHAR(100) NULL")

def abstract_sql(store):
    for name in (
        'binary_type', 'max_varchar', 'ddl_implicit_commit',
        'create_table_epilogue', 'sequence_type', 'limit_style',
        'int_type', 'clob_type'):
        store.sql("""
            UPDATE configvar
               SET configvar_name = ?
             WHERE configvar_name = ?""", ('sql.' + name, name))

def populate_pubkeys(store):
    store.log.info("Finding short public key addresses.")
    count = 0
    while True:
        rows = store.selectall("""
            SELECT txout_id, txout_scriptPubKey
              FROM txout
             WHERE pubkey_id IS NULL
               AND txout_scriptPubKey BETWEEN ? AND ?
             LIMIT 3000""",
                               (store.binin("\x21"), store.binin("\x22")))
        if not rows:
            break
        for txout_id, db_script in rows:
            script = store.binout(db_script)
            pubkey_id = store.script_to_pubkey_id(script)
            if pubkey_id > 0:
                store.sql("UPDATE txout SET pubkey_id = ? WHERE txout_id = ?",
                          (pubkey_id, txout_id))
                count += 1
        store.log.info("Found %d", count)

upgrades = [
    ('AbeNoStats1', add_datadir_loader),     # Fast
    ('AbeNoStats2', abstract_sql),
    ('AbeNoStats3', populate_pubkeys),       # Minutes
    ('AbeNoStats4', None),
]

def upgrade_schema(store):
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
