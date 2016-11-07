#!/usr/bin/env python
# Prototype database validation script.  Same args as abe.py.

# Copyright(C) 2011,2014 by Abe developers.

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

import sys
import getopt
import DataStore
import util
import logging

# List of block statistics to check.
BLOCK_STATS_LIST = [
    'value_in',
    'value_out',
    'total_satoshis',
    'total_seconds',
    'satoshi_seconds',
    'total_ss',
    'ss_destroyed',
]


class AbeVerify:
    def __init__(self, store, logger):
        self.store = store
        self.logger = logger
        self.block_min = None
        self.block_max = None

        self.ckmerkle = False
        self.ckbti    = False
        self.ckstats  = False

        self.repair = False
        self.blkstats = BLOCK_STATS_LIST
        self.stats = {
            'mchecked': 0, # Blocks checked for Merkel root
            'mbad':     0, # Merkle errors
            'schecked': 0, # Blocks checked for stats
            'sbad':     0, # Blocks with any stats error
            'btiblks':    0, # Blocks checked for block_txin links
            'btichecked': 0, # block_txin txin_id's checked
            'btimiss':    0, # Missing txin_id's
            'btibad':     0, # txin_id's linked to wrong block (untested)
        }


    def verify_blockchain(self, chain_id, chain):
        # Reset stats
        self.stats = {key: 0 for key in self.stats}

        params = (chain_id,)
        if self.block_min is not None:
            params += (self.block_min,)
        if self.block_max is not None:
            params += (self.block_max,)

        # Retain height after loop
        block_height = 0
        for block_id, block_height in self.store.selectall("""
            SELECT block_id, block_height
              FROM chain_candidate
             WHERE chain_id = ?""" + (
            "" if self.block_min is None else """
               AND block_height >= ?""") + (
            "" if self.block_max is None else """
               AND block_height <= ?""") + """
          ORDER BY block_height ASC, block_id ASC""", params):

            if block_height is None:
                self.logger.error("Block id %d has no height (skipped)", block_id)
                continue

            if self.ckmerkle:
                self.verify_tx_merkle_hash(block_id, chain)
                self.procstats("Merkle trees", block_height,
                    self.stats['mchecked'], self.stats['mbad'])

            if self.ckbti:
                self.verify_block_txin(block_id, chain_id)
                self.procstats("Block txins", block_height,
                    self.stats['btichecked'],
                    self.stats['btimiss'] + self.stats['btibad'],
                    blocks=self.stats['btiblks'])

            if self.ckstats:
                self.verify_block_stats(block_id, chain_id)
                self.procstats("Block stats", block_height,
                    self.stats['schecked'], self.stats['sbad'])

            if self.repair:
                # XXX: Make this time-based? The goal is to not hold locks for
                # too long, yet avoid committing many times per seconds on the
                # earliest blocks
                self.store.commit()

        if self.ckmerkle:
            self.procstats("Merkle trees", block_height, self.stats['mchecked'],
                self.stats['mbad'], last=True)
        if self.ckbti:
            self.procstats("Block txins", block_height,
                self.stats['btichecked'],
                self.stats['btimiss'] + self.stats['btibad'],
                blocks=self.stats['btiblks'], last=True)
        if self.ckstats:
            self.procstats("Block stats", block_height, self.stats['schecked'],
                self.stats['sbad'], last=True)

        if self.repair:
            self.store.commit()


    def procstats(self, name, height, checked, bad, blocks=False, last=False):
        if blocks is False:
            blocks = checked

        if (blocks % 1000 == 0) is not last:
            lst = ("last " if last else "")
            self.logger.warning("%d %s (%sheight: %d): %s bad",
                                checked, name, lst, height, bad)


    def verify_tx_merkle_hash(self, block_id, chain):
        block_height, merkle_root, num_tx = self.store.selectrow("""
            SELECT b.block_height, b.block_hashMerkleRoot, b.block_num_tx
              FROM block b
             WHERE b.block_id = ?""", (block_id,))
        merkle_root = self.store.hashout(merkle_root)
        tree = []
        for (tx_hash,) in self.store.selectall("""
            SELECT tx.tx_hash
              FROM block_tx bt
              JOIN tx ON (bt.tx_id = tx.tx_id)
             WHERE bt.block_id = ?
             ORDER BY bt.tx_pos""", (block_id,)):
            tree.append(self.store.hashout(tx_hash))
        # Log single error for either num_tx bad merkle
        bad = 0
        if len(tree) != num_tx:
            self.logger.info("block %d (id %d): block_num_tx=%d but found %d",
                             block_height, block_id, num_tx, len(tree))
            bad = 1
        root = chain.merkle_root(tree) or util.NULL_HASH
        if root != merkle_root:
            self.logger.info("block %d (id %s): block_hashMerkleRoot mismatch",
                             block_height, block_id)
            bad = 1
        self.stats['mbad'] += bad
        self.stats['mchecked'] += 1


    def verify_block_txin(self, block_id, chain_id):
        rows = self.store.selectall("""
            SELECT txin_id, out_block_id
              FROM block_txin
             WHERE block_id = ?
          ORDER BY txin_id ASC""", (block_id,))

        known_ids = {row[0]: row[1] for row in rows}
        checks = len(rows)
        missing = set()
        redo = set()

        if checks:
            # Find all missing txin_id's
            for txin_id, in self.store.selectall("""
                SELECT txin.txin_id
                  FROM block_tx bt
                  JOIN txin ON (txin.tx_id = bt.tx_id)
                  JOIN txout ON (txin.txout_id = txout.txout_id)
                  JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
                  JOIN block ob ON (obt.block_id = ob.block_id)
                 WHERE bt.block_id = ?
                   AND ob.block_chain_work IS NOT NULL
                   AND bt.tx_pos <> 0
              ORDER BY txin.txin_id ASC""", (block_id,)):

                if txin_id not in known_ids:
                    missing.add(txin_id)
                    self.logger.info("block id %d: txin_id %d not found in "
                                     "block_txin", block_id, txin_id)

            # Check all txin_id's already present (what we would insert)
            for txin_id, obt_id in self._populate_block_txin(int(block_id),
                    skip_txin=missing, check_only=True):
                if obt_id != known_ids[txin_id]:
                    redo.add(txin_id)
                    self.logger.info("block id %d: txin_id %d out_block_id "
                                     "is %d (should be %s)", block_id, txin_id,
                                     known_ids[txin_id], obt_id)

        if (redo or missing) and self.repair:
            # Delete erroneous block_txin's and insert both sets
            for txin_id in redo:
                self.store.sql("""
                    DELETE FROM block_txin
                          WHERE block_id = ?
                            AND txin_id = ?""", (block_id, txin_id))

            # Take out redo's from known_ids
            skip_ids = set(known_ids).difference(redo)
            self._populate_block_txin(int(block_id), skip_txin=skip_ids)
            self.logger.info("block id %d: txin links repaired", block_id)


        # Record stats
        self.stats['btimiss'] += len(missing)
        self.stats['btibad']  += len(redo)
        self.stats['btiblks'] += 1
        self.stats['btichecked'] += checks + len(missing)


    def verify_block_stats(self, block_id, chain_id):
        block_height, nTime, value_in, value_out, total_satoshis, \
        total_seconds, satoshi_seconds, total_ss, ss_destroyed, \
        prev_nTime, prev_satoshis, prev_seconds, prev_ss, \
        prev_total_ss = self.store.selectrow("""
            SELECT b.block_height, b.block_nTime, b.block_value_in,
                   b.block_value_out, b.block_total_satoshis,
                   b.block_total_seconds, b.block_satoshi_seconds,
                   b.block_total_ss, b.block_ss_destroyed,
                   prev.block_nTime, prev.block_total_satoshis,
                   prev.block_total_seconds, prev.block_satoshi_seconds,
                   prev.block_total_ss
              FROM block b
         LEFT JOIN block prev ON (b.prev_block_id = prev.block_id)
             WHERE b.block_id = ?""", (block_id,))

        if None in (prev_satoshis, prev_seconds, prev_ss, prev_total_ss):
            if block_height == 0:
                # For genesis block, fill in prev block stats with 0's
                prev_satoshis = prev_seconds = prev_ss = prev_total_ss = 0
                # This will make this block's total_seconds 0
                prev_nTime = nTime
            elif self.repair:
                raise Exception("Repair with broken prev block, dazed and "
                    "confused... block %s (height %s): %s" % (
                    block_id, block_height, str((prev_satoshis, prev_seconds,
                                                 prev_ss, prev_total_ss))))
            else:
                # Prev block contain broken data; cannot check current (and
                # it is likely bad as well)
                self.logger.info("block %d (id %d): Bad prev block, skipping "
                                 "as assumed bad block", block_height, block_id)
                self.stats['schecked'] += 1
                self.stats['sbad'] += 1
                return

        # A dict makes easier comparison
        d = {
            'value_in': value_in,
            'value_out': value_out,
            'total_satoshis': total_satoshis,
            'total_seconds': total_seconds,
            'satoshi_seconds': satoshi_seconds,
            'total_ss': total_ss,
            'ss_destroyed': ss_destroyed
        }

        b = dict()

        # Modified version of self.store.get_received_and_last_block_id()
        b['value_in'], = self.store.selectrow("""
            SELECT COALESCE(value_sum, 0)
              FROM chain c LEFT JOIN (
                SELECT cc.chain_id, SUM(txout.txout_value) value_sum
                  FROM txout
                  JOIN txin             ON (txin.txout_id = txout.txout_id)
                  JOIN block_tx         ON (block_tx.tx_id = txin.tx_id)
                  JOIN block b          ON (b.block_id = block_tx.block_id)
                  JOIN chain_candidate cc ON (cc.block_id = b.block_id)
                WHERE
                  cc.chain_id = ? AND
                  b.block_id = ?
                GROUP BY cc.chain_id
              ) a ON (c.chain_id = a.chain_id)
            WHERE c.chain_id = ?""", (chain_id, block_id, chain_id))
        b['value_in'] = (b['value_in'] if b['value_in'] else 0)

        # Modified version of self.store.get_sent_and_last_block_id()
        b['value_out'], = self.store.selectrow("""
            SELECT COALESCE(value_sum, 0)
              FROM chain c LEFT JOIN (
                SELECT cc.chain_id, SUM(txout.txout_value) value_sum
                  FROM txout
                  JOIN block_tx           ON (block_tx.tx_id = txout.tx_id)
                  JOIN block b            ON (b.block_id = block_tx.block_id)
                  JOIN chain_candidate cc ON (cc.block_id = b.block_id)
                WHERE
                  cc.chain_id = ? AND
                  b.block_id = ?
                GROUP BY cc.chain_id
              ) a ON (c.chain_id = a.chain_id)
             WHERE c.chain_id = ?""", (chain_id, block_id, chain_id))
        b['value_out'] = (b['value_out'] if b['value_out'] else 0)

        b['total_seconds'] = prev_seconds + nTime - prev_nTime
        ss_created = prev_satoshis * (nTime - prev_nTime)
        b['total_ss'] = prev_total_ss + ss_created

        tx_ids = map(
            lambda row: row[0],
            self.store.selectall("""
                SELECT tx_id
                  FROM block_tx
                 WHERE block_id = ?
              ORDER BY tx_pos ASC""", (block_id,)))
        b['ss_destroyed'] = 0

        # Modified version of self.store._get_block_ss_destroyed()
        block_ss_destroyed = 0
        for tx_id in tx_ids:
            destroyed = 0
            # TODO: Warn if inner loop isn't used
            # Don't do the math in SQL as we risk losing precision
            for txout_value, block_nTime in self.store.selectall("""
                SELECT COALESCE(txout_approx.txout_approx_value, 0),
                       b.block_nTime
                  FROM block_txin bti
                  JOIN txin ON (bti.txin_id = txin.txin_id)
                  JOIN txout_approx ON (txin.txout_id = txout_approx.txout_id)
                  JOIN block_tx obt ON (txout_approx.tx_id = obt.tx_id)
                  JOIN block b ON (obt.block_id = b.block_id)
                 WHERE bti.block_id = ? AND txin.tx_id = ?""",
                                            (block_id, tx_id)):
                destroyed += txout_value * (nTime - block_nTime)
            b['ss_destroyed'] += destroyed

        b['satoshi_seconds'] = prev_ss + ss_created - b['ss_destroyed']

        # Modified version of self.store.tx_find_id_and_value (finding
        # value_destroyed only)
        value_destroyed = 0
        for tid in tx_ids:
            destroyed, = self.store.selectrow("""
                SELECT SUM(txout.txout_value) - SUM(
                 CASE WHEN txout.pubkey_id IS NOT NULL AND txout.pubkey_id <= 0
                      THEN 0 ELSE txout.txout_value END)
                  FROM tx
                  LEFT JOIN txout ON (tx.tx_id = txout.tx_id)
                 WHERE tx.tx_id = ?""", (tid,))
            value_destroyed += destroyed

        b['total_satoshis'] = prev_satoshis + b['value_out'] \
                              - b['value_in'] - value_destroyed

        if None in b.values():
            raise Exception("Stats computation error: block %d (height %d): "
                            "%s" % (block_id, block_height, str(b)))

        # Finally... Check stats values match between d and b
        badcheck = False
        for key in self.blkstats:
            if d[key] != b[key]:
                badcheck = True
                self.logger.info("block %d (id %d): %s do not match: %s "
                                 "(should be %s)", block_height, block_id,
                                 key, d[key], b[key])
        self.stats['schecked'] += 1
        if badcheck and self.repair:
            self.store.sql("""
                UPDATE block
                   SET block_value_in = ?,
                       block_value_out = ?,
                       block_total_seconds = ?,
                       block_total_satoshis = ?,
                       block_satoshi_seconds = ?,
                       block_total_ss = ?,
                       block_ss_destroyed = ?
                 WHERE block_id = ?""",
                      (self.store.intin(b['value_in']),
                       self.store.intin(b['value_out']),
                       self.store.intin(b['total_seconds']),
                       self.store.intin(b['total_satoshis']),
                       self.store.intin(b['satoshi_seconds']),
                       self.store.intin(b['total_ss']),
                       self.store.intin(b['ss_destroyed']),
                       block_id))
            self.logger.info("block %d (id %d): stats repaired",
                             block_height, block_id)

        if badcheck:
            self.stats['sbad'] += 1


    # Copied and modified from the same function in DataStore.py
    def _populate_block_txin(self, block_id, skip_txin=set(), check_only=False):
        # Create rows in block_txin.  In case of duplicate transactions,
        # choose the one with the lowest block ID.  XXX For consistency,
        # it should be the lowest height instead of block ID.
        txin_oblocks = {}
        ret = []
        for txin_id, oblock_id in self.store.selectall("""
            SELECT txin.txin_id, obt.block_id
              FROM block_tx bt
              JOIN txin ON (txin.tx_id = bt.tx_id)
              JOIN txout ON (txin.txout_id = txout.txout_id)
              JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
              JOIN block ob ON (obt.block_id = ob.block_id)
             WHERE bt.block_id = ?
               AND ob.block_chain_work IS NOT NULL
          ORDER BY txin.txin_id ASC, obt.block_id ASC""", (block_id,)):

            # Repair only missing txins
            if txin_id in skip_txin:
                continue

            # Save all candidate, lowest ID might not be a descendant if we
            # have multiple block candidates
            txin_oblocks.setdefault(txin_id, []).append(oblock_id)

        for txin_id, oblock_ids in txin_oblocks.iteritems():
            for oblock_id in oblock_ids:
                if self.store.is_descended_from(block_id, int(oblock_id)):
                    if check_only:
                        # Skip update part to test what should be inserted
                        # NB: can't use yield as we also call method normally!
                        ret.append((txin_id, oblock_id))
                        continue
                    # Store lowest block id that is descended from our block
                    self.store.sql("""
                        INSERT INTO block_txin (block_id, txin_id, out_block_id)
                        VALUES (?, ?, ?)""", (block_id, txin_id, oblock_id))
        return ret


def main(argv):
    cmdline = util.CmdLine(argv)
    cmdline.usage = lambda: \
        """Usage: verify.py --dbtype=MODULE --connect-args=ARGS [checks]

  Check database consistency

  Chain selection:
    --chain LIST    Comma-separated list of chains to check (Default: all)

  Checks:
    --check-all     Check everything (overrides all other check options)
    --merkle-roots  Check merkle root hashes against block's transaction
    --block-txins   Check block txin-to-out-block links used in block
                    statistics computation
    --block-stats   Check block statistics computed from prev blocks and
                    transactions

  Options:
    --verbose       Print all errors found (default)
    --quiet         Print only progress info and error summary
    --silent        Print nothing; no feedback beside return code
    --min-height N  Check only blocks starting at height N
    --max-height N  Stop checking blocks above height N
    --blkstats LIST Comma-separated list of block statistics to check
                    Default: all valid values:
                      """ + ','.join(BLOCK_STATS_LIST) + """
    --repair        Attempt to repair the database (not all checks support
                    repair)

  Warning: Some checks rely on previous blocks to have valid information.
   Testing from a specific height does not guarantee the previous blocks are
   valid and while the computed data may be relatively valid the whole thing
   could still be totally off.

  The checks can generate a lot of output in the default mode (--verbose). To
  limit output to progress messages and results use the --quiet option.
"""

    store, argv = cmdline.init()
    if store is None:
        return 0

    logger = logging.getLogger("verify")
    # Override any defined loggers from abe's config
    logging.root.handlers = []
    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(asctime)s: %(name)s: %(message)s")

    chk = AbeVerify(store, logger)

    try:
        opts, args = getopt.getopt(argv, "", [
            'chain=',
            'check-all',
            'merkle-roots',
            'block-txins',
            'block-stats',
            'verbose',
            'quiet',
            'silent',
            'min-height=',
            'max-height=',
            'blkstats=',
            'repair',
        ])
    except getopt.GetoptError as e:
        print e.msg, "\n\n", cmdline.usage()
        return 1

    chains = None
    err = 0
    for opt, arg in opts:
        if opt == '--chain':
            chains = arg.split(',')
        if opt == '--check-all':
            chk.ckmerkle, chk.ckbti, chk.ckstats = True, True, True
        if opt == '--merkle-roots':
            chk.ckmerkle = True
        if opt == '--block-txins':
            chk.ckbti = True
        if opt == '--block-stats':
            chk.ckstats = True
        if opt == '--verbose':
            logger.setLevel('INFO')
        if opt == '--quiet':
            logger.setLevel('WARNING')
        if opt == '--silent':
            logger.setLevel('ERROR')
        if opt == '--min-height':
            chk.block_min = int(arg)
        if opt == '--max-height':
            chk.block_max = int(arg)
        if opt == '--blkstats':
            chk.blkstats = arg.split(',')
        if opt == '--repair':
            chk.repair = True

    if args:
        print "Extra argument: %s!\n\n" % args[0], cmdline.usage()
        return 1

    if True not in (chk.ckmerkle, chk.ckbti, chk.ckstats):
        print "No checks selected!\n\n", cmdline.usage()
        return 1


    for chain_id, in store.selectall("""
        SELECT chain_id FROM chain ORDER BY chain_id DESC"""):
        chain = store.chains_by.id[chain_id]
        if chains is not None:
            if chain.name not in chains:
                continue
            chains.remove(chain.name)

        logger.warning("Checking %s chain (id %d) at height %d",
                chain.name, chain_id, (chk.block_min if chk.block_min else 0))

        try:
            chk.verify_blockchain(chain_id, chain)
        except KeyboardInterrupt:
            # Prevents some DB warnings warnings
            store.close()
            raise

        endmsg="Chain %s: %d blocks checked"
        endparams = (max(chk.stats['mchecked'], chk.stats['schecked']),)
        err += max(chk.stats['mbad'], chk.stats['sbad'])
        if chk.ckmerkle and chk.stats['mbad']:
            endmsg += ", %d bad merkle tree hashes"
            endparams += (chk.stats['mbad'],)
        if chk.ckbti and chk.stats['btimiss']:
            endmsg += ", %d missing block txins"
            endparams += (chk.stats['btimiss'],)
        if chk.ckbti and chk.stats['btibad']:
            endmsg += ", %d bad block txins"
            endparams += (chk.stats['btibad'],)
        if chk.ckstats and chk.stats['sbad']:
            endmsg += ", %d bad blocks stats"
            endparams += (chk.stats['sbad'],)
        if len(endparams) == 1:
            endmsg += ", no error found"
        logger.warning(endmsg, chain.name, *endparams)

    if chains:
        err += 1
        logger.warning("%d chain%s not found: %s",
            len(chains),
            ("s" if len(chains) > 1 else ""),
            ', '.join(chains),
        )
    return err and 1

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print >>sys.stderr, "\rInterrupted!"
        sys.exit(1)
