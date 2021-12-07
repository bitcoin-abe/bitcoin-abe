#!/usr/bin/env python

# Copyright(C) 2012,2014 by Abe developers.

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

"""Load blocks in different order for testing."""

import sys
from Abe import util
from Abe.data_store import CmdLine
from Abe.streams import BCDataStream


def mixup_blocks(store, data_stream, count, datadir_chain=None, seed=None):
    """mixup_blocks"""
    bytes_done = 0
    offsets = []

    for i in range(count):
        if data_stream.read_cursor + 8 <= len(data_stream.input):
            offsets.append(data_stream.read_cursor)
            magic = data_stream.read_bytes(4)
            length = data_stream.read_int32()
            data_stream.read_cursor += length
            if data_stream.read_cursor <= len(data_stream.input):
                continue
        raise IOError(f"End of input after {i} blocks")

    if seed > 1 and seed <= count:
        for i in range(0, seed * int(count / seed), seed):
            offsets[i : i + seed] = offsets[i : i + seed][::-1]
    elif seed == -3:
        for i in range(0, 3 * int(count / 3), 3):
            offsets[i : i + 3] = offsets[i + 1 : i + 3] + [offsets[i]]
        print(offsets)
    elif seed:
        offsets = offsets[::-1]  # XXX want random

    for offset in offsets:
        data_stream.read_cursor = offset
        magic = data_stream.read_bytes(4)
        length = data_stream.read_int32()

        # Assume blocks obey the respective policy if they get here.
        chain = datadir_chain
        if chain is None:
            chain = store.chains_by.magic.get(magic)
        if chain is None:
            data_stream.read_cursor = offset
            raise ValueError(
                f"Chain not found for magic number {repr(magic)} in block file at offset {offset}."
            )

        # XXX pasted out of DataStore.import_blkdat, which has since undergone
        # considerable changes.
        end = data_stream.read_cursor + length

        _hash = util.double_sha256(
            data_stream.input[data_stream.read_cursor : data_stream.read_cursor + 80]
        )
        # XXX should decode target and check hash against it to
        # avoid loading garbage data.  But not for merged-mined or
        # CPU-mined chains that use different proof-of-work
        # algorithms.  Time to resurrect policy_id?

        block_row = store.selectrow(
            """
            SELECT block_id, block_height, block_chain_work,
                   block_nTime, block_total_seconds,
                   block_total_satoshis, block_satoshi_seconds
              FROM block
             WHERE block_hash = ?
        """,
            (store.hashin(_hash),),
        )

        if block_row:
            # Block header already seen.  Don't import the block,
            # but try to add it to the chain.
            if chain is not None:
                block = {
                    "block_id": block_row[0],
                    "height": block_row[1],
                    "chain_work": store.binout_int(block_row[2]),
                    "nTime": block_row[3],
                    "seconds": block_row[4],
                    "satoshis": block_row[5],
                    "ss": block_row[6],
                }
                if store.selectrow(
                    """
                    SELECT 1
                      FROM chain_candidate
                     WHERE block_id = ?
                       AND chain_id = ?""",
                    (block["block_id"], chain.id),
                ):
                    store.log.info(
                        "block %d already in chain %d", block["block_id"], chain.id
                    )
                    block = None
                else:
                    if block["height"] == 0:
                        block["hashPrev"] = util.GENESIS_HASH_PREV
                    else:
                        block["hashPrev"] = "dummy"  # Fool adopt_orphans.
                    store.offer_block_to_chains(block, frozenset([chain.id]))
        else:
            block = chain.ds_parse_block(data_stream)
            block["hash"] = _hash
            chain_ids = frozenset([] if chain is None else [chain.id])
            store.import_block(block, chain_ids=chain_ids)
            if data_stream.read_cursor != end:
                store.log.debug(
                    "Skipped %d bytes at block end", end - data_stream.read_cursor
                )

        bytes_done += length
        if bytes_done >= store.commit_bytes:
            store.log.debug("commit")
            store.commit()
            bytes_done = 0

    if bytes_done > 0:
        store.commit()


def main(argv):
    """main"""
    conf = {
        "count": 200,
        "seed": 1,
        "blkfile": None,
    }
    cmdline = CmdLine(argv, conf)
    cmdline.usage = (
        lambda: """Usage: python -m Abe.mixup [-h] [--config=FILE] [--CONFIGVAR=VALUE]...

Load blocks out of order.

  --help                    Show this help message and exit.
  --config FILE             Read options from FILE.
  --count NUMBER            Load COUNT blocks.
  --blkfile FILE            Load the first COUNT blocks from FILE.
  --seed NUMBER             Random seed (not implemented; 0=file order).

All configuration variables may be given as command arguments."""
    )

    store, argv = cmdline.init()
    if store is None:
        return 0
    args = store.args

    if args.blkfile is None:
        raise ValueError("--blkfile is required.")

    data_stream = BCDataStream()
    file = open(args.blkfile, "rb")
    data_stream.map_file(file, 0)
    file.close()
    mixup_blocks(store, data_stream, int(args.count), None, int(args.seed or 0))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
