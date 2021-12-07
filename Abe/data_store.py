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

"""data_store.py: back end database access for Abe.
This module combines three functions that might be better split up:
1. Abe's schema
2. Abstraction over the schema for importing blocks, etc.
3. Code to load data by scanning blockfiles or using JSON-RPC."""

# pylint: disable=too-many-lines invalid-name fixme

import os
import re
import time
import errno
import logging
from logging import config as logging_config
from random import randint
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from chains.base_chain import BaseChain
from . import readconf, SqlAbstraction, chains, util, upgrade, sql, genesis_tx
from .chains import CHAIN_CONFIG

from .constants import (
    CONFIG_DEFAULTS,
    SCHEMA_VERSION,
    NULL_PUBKEY_HASH,
    NULL_PUBKEY_ID,
    SCHEMA_TYPE,
    WORK_BITS,
    PUBKEY_ID_NETWORK_FEE,
    MAX_PUBKEY,
)
from .exceptions import (
    InvalidBlock,
    MerkleRootMismatch,
    MalformedHash,
    MalformedAddress,
    SerializationError,
)
from .merkle import Merkle
from .streams import BCDataStream
from .typing import Block  # , Transaction, TxIn
from .util import b2hex, hex2b

# bitcointools -- modified deserialize.py to return raw transaction


class DataStore:

    """
    Bitcoin data storage class based on DB-API 2 and standard SQL with
    workarounds to support SQLite3, PostgreSQL/psycopg2, MySQL,
    Oracle, ODBC, and IBM DB2.
    """

    def __init__(self, args):
        """
        Open and store a connection to the SQL database.

        args.dbtype should name a DB-API 2 driver module, e.g.,
        "sqlite3".

        args.connect_args should be an argument to the module's
        connect() method, or None for no argument, or a list of
        arguments, or a dictionary of named arguments.

        args.datadir names Bitcoin data directories containing
        blk0001.dat to scan for new blocks.
        """
        if args.datadir is None:
            args.datadir = util.determine_db_dir()
        if isinstance(args.datadir, str):
            args.datadir = [args.datadir]

        self.args = args
        self.log = logging.getLogger(__name__)

        self.rpclog = logging.getLogger(__name__ + ".rpc")
        if not args.log_rpc:
            self.rpclog.setLevel(logging.ERROR)

        if args.dbtype is None:
            self.log.warning("dbtype not configured, see abe.conf for examples")
            self.dbmodule = None
            self.config = CONFIG_DEFAULTS.copy()
            self.datadirs = []
            self.use_firstbits = CONFIG_DEFAULTS["use_firstbits"]
            self._sql: SqlAbstraction.SqlAbstraction = None
            return
        self.dbmodule = __import__(args.dbtype)

        sql_args = lambda: 1
        sql_args.module = self.dbmodule
        sql_args.connect_args = args.connect_args
        sql_args.binary_type = args.binary_type
        sql_args.int_type = args.int_type
        sql_args.log_sql = args.log_sql
        sql_args.prefix = "abe_"
        sql_args.config = {}
        self.sql_args = sql_args
        self.set_db(None)
        self.init_sql()

        self._blocks = {}

        # Read the CONFIG and CONFIGVAR tables if present.
        self.config = self._read_config()

        if self.config is None:
            self.keep_scriptsig = args.keep_scriptsig
        elif "keep_scriptsig" in self.config:
            self.keep_scriptsig = self.config.get("keep_scriptsig") == "true"
        else:
            self.keep_scriptsig = CONFIG_DEFAULTS["keep_scriptsig"]

        self.refresh_ddl()

        if self.config is None:
            self.initialize()
        else:
            self.init_sql()

            if self.config["schema_version"] == SCHEMA_VERSION:
                pass
            elif args.upgrade:

                upgrade.upgrade_schema(self)
            else:
                raise Exception(
                    f"Database schema version ({self.config['schema_version']}) \
                        does not match software ({SCHEMA_VERSION}). \
                        Please run with --upgrade to convert database."
                )
        self._sql.auto_reconnect = True

        if args.rescan:
            self.sql("UPDATE datadir SET blkfile_number=1, blkfile_offset=0")

        self._init_datadirs()
        self.init_chains()

        self.commit_bytes = args.commit_bytes
        if self.commit_bytes is None:
            self.commit_bytes = 0  # Commit whenever possible.
        else:
            self.commit_bytes = int(self.commit_bytes)
        self.bytes_since_commit = 0

        self.use_firstbits = self.config["use_firstbits"] == "true"

        for hex_tx in args.import_tx:
            chain_name = None
            if isinstance(hex_tx, dict):
                chain_name = hex_tx.get("chain")
                hex_tx = hex_tx.get("tx")
            self.maybe_import_binary_tx(chain_name, str(hex_tx).decode("hex"))

        self.default_loader = args.default_loader

        self.rpc_load_mempool = args.rpc_load_mempool

        self.default_chain = args.default_chain

        self.rpcuser = args.rpcuser

        self.rpcpassword = args.rpcpassword

        self.commit()
        self.binin: Callable
        self.binin_hex: Callable
        self.binin_int: Callable
        self.binout: Callable
        self.binout_hex: Callable
        self.binout_int: Callable
        self.hashin: Callable
        self.hashin_hex: Callable
        self.hashin_int: Callable
        self.hashout: Callable
        self.hashout_hex: Callable
        self.intin: Callable
        self.mempool_tx: Callable

    def set_db(self, data_base: SqlAbstraction.SqlAbstraction) -> None:
        """set_db"""
        self._sql = data_base

    def get_db(self):
        """get_db"""
        return self._sql

    def connect(self):
        """connect"""
        return self._sql.connect()

    def reconnect(self):
        """reconnect"""
        return self._sql.reconnect()

    def close(self):
        """close"""
        self._sql.close()

    def commit(self):
        """commit"""
        self._sql.commit()

    def rollback(self):
        """rollback"""
        if self._sql is not None:
            self._sql.rollback()

    def sql(self, stmt, params=()):
        """sql"""
        self._sql.sql(stmt, params)

    def ddl(self, stmt):
        """ddl"""
        self._sql.ddl(stmt)

    def selectrow(self, stmt, params=()):
        """selectrow"""
        return self._sql.selectrow(stmt, params)

    def selectall(self, stmt, params=()):
        """selectall"""
        return self._sql.selectall(stmt, params)

    def rowcount(self):
        """rowcount"""
        return self._sql.rowcount()

    def create_sequence(self, key):
        """create_sequence"""
        self._sql.create_sequence(key)

    def drop_sequence(self, key):
        """drop_sequence"""
        self._sql.drop_sequence(key)

    def new_id(self, key: str) -> int:
        """new_id"""
        return int(self._sql.new_id(key))

    def init_sql(self):
        """init_sql"""
        sql_args = self.sql_args
        if hasattr(self, "config"):
            for name in self.config.keys():
                if name.startswith("sql."):
                    sql_args.config[name[len("sql.") :]] = self.config[name]
        if self._sql:
            self._sql.close()  # XXX Could just set_flavour.
        self.set_db(SqlAbstraction.SqlAbstraction(sql_args))
        self.init_binfuncs()

    def init_binfuncs(self):
        """init_binfuncs"""
        self.binin = self._sql.binin
        self.binin_hex = self._sql.binin_hex
        self.binin_int = self._sql.binin_int
        self.binout = self._sql.binout
        self.binout_hex = self._sql.binout_hex
        self.binout_int = self._sql.binout_int
        self.intin = self._sql.intin
        self.hashin = self._sql.revin
        self.hashin_hex = self._sql.revin_hex
        self.hashout = self._sql.revout
        self.hashout_hex = self._sql.revout_hex

    def _read_config(self):
        # Read table CONFIGVAR if it exists.
        config = {}
        try:
            for name, value in self.selectall(
                """
                SELECT configvar_name, configvar_value
                  FROM configvar"""
            ):
                config[name] = "" if value is None else value
            if config:
                return config

        except self.dbmodule.DatabaseError:
            try:
                self.rollback()
            except Exception:
                pass

        # Read legacy table CONFIG if it exists.
        try:
            row = self.selectrow(
                """
                SELECT schema_version, binary_type
                  FROM config
                 WHERE config_id = 1"""
            )
            schema_version, btype = row
            return {"schema_version": schema_version, "binary_type": btype}
        except Exception:
            try:
                self.rollback()
            except Exception:
                pass

        # Return None to indicate no schema found.
        return None

    def _init_datadirs(self):
        """Parse self.args.datadir, create self.datadirs."""
        if self.args.datadir == []:
            self.datadirs = []
            return

        datadirs = {}
        for row in self.selectall(
            """
            SELECT datadir_id, dirname, blkfile_number, blkfile_offset,
                   chain_id
              FROM datadir"""
        ):
            rid, rdir, num, offs, chain_id = row
            datadirs[dir] = {
                "id": rid,
                "dirname": rdir,
                "blkfile_number": int(num),
                "blkfile_offset": int(offs),
                "chain_id": None if chain_id is None else int(chain_id),
                "loader": None,
            }

        # print("datadirs: %r" % datadirs)

        # By default, scan every dir we know.  This doesn't happen in
        # practise, because abe.py sets ~/.bitcoin as default datadir.
        if self.args.datadir is None:
            self.datadirs = datadirs.values()
            return

        def lookup_chain_id(name):
            row = self.selectrow(
                "SELECT chain_id FROM chain WHERE chain_name = ?", (name,)
            )
            return None if row is None else int(row[0])

        self.datadirs = []
        for dircfg in self.args.datadir:
            loader = None
            conf = None

            if isinstance(dircfg, dict):
                # print("dircfg is dict: %r" % dircfg)  # XXX
                dirname = dircfg.get("dirname")
                if dirname is None:
                    raise ValueError(
                        "Missing dirname in datadir configuration: " + str(dircfg)
                    )
                if dirname in datadirs:
                    name = datadirs[dirname]
                    name["loader"] = dircfg.get("loader")
                    name["conf"] = dircfg.get("conf")
                    if name["chain_id"] is None and "chain" in dircfg:
                        name["chain_id"] = lookup_chain_id(dircfg["chain"])
                    self.datadirs.append(name)
                    continue

                loader = dircfg.get("loader")
                conf = dircfg.get("conf")
                chain_id = dircfg.get("chain_id")
                if chain_id is None:
                    chain_name = dircfg.get("chain")
                    chain_id = lookup_chain_id(chain_name)

                    if chain_id is None and chain_name is not None:
                        chain_id = self.new_id("chain")

                        code3 = dircfg.get("code3")
                        if code3 is None:
                            # XXX Should default via policy.
                            code3 = "000" if chain_id > 999 else f"{chain_id}"

                        addr_vers = dircfg.get("address_version")
                        if addr_vers is None:
                            addr_vers = "\0"
                        elif isinstance(addr_vers, str):
                            addr_vers = addr_vers.encode("latin_1")

                        script_addr_vers = dircfg.get("script_addr_vers")
                        if script_addr_vers is None:
                            script_addr_vers = "\x05"
                        elif isinstance(script_addr_vers, str):
                            script_addr_vers = script_addr_vers.encode("latin_1")

                        decimals = dircfg.get("decimals")
                        if decimals is not None:
                            decimals = int(decimals)

                        # XXX Could do chain_magic, but this datadir won't
                        # use it, because it knows its chain.

                        self.sql(
                            """
                            INSERT INTO chain (
                                chain_id, chain_name, chain_code3,
                                chain_address_version, chain_script_addr_vers, chain_policy,
                                chain_decimals
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                            (
                                chain_id,
                                chain_name,
                                code3,
                                self.binin(addr_vers),
                                self.binin(script_addr_vers),
                                dircfg.get("policy", chain_name),
                                decimals,
                            ),
                        )
                        self.commit()
                        self.log.warning(
                            "Assigned chain_id %d to %s", chain_id, chain_name
                        )

            elif dircfg in datadirs:
                self.datadirs.append(datadirs[dircfg])
                continue
            else:
                # Not a dict.  A string naming a directory holding
                # standard chains.
                dirname = dircfg
                chain_id = None

            directory_name = {
                "id": self.new_id("datadir"),
                "dirname": dirname,
                "blkfile_number": 1,
                "blkfile_offset": 0,
                "chain_id": chain_id,
                "loader": loader,
                "conf": conf,
            }
            self.datadirs.append(directory_name)

    def init_chains(self):
        """init_chains"""
        self.chains_by = lambda: 0
        self.chains_by.id = {}
        self.chains_by.name = {}
        self.chains_by.magic = {}

        # Legacy config option.
        no_bit8_chains = self.args.ignore_bit8_chains or []
        if isinstance(no_bit8_chains, str):
            no_bit8_chains = [no_bit8_chains]
        row = self.selectall(
            """
            SELECT chain_id, chain_magic, chain_name, chain_code3,
                    chain_address_version, chain_script_addr_vers,
                    chain_policy, chain_decimals
            FROM chain"""
        )
        for (
            chain_id,
            magic,
            chain_name,
            chain_code3,
            address_version,
            script_addr_vers,
            chain_policy,
            chain_decimals,
        ) in row:
            chain: BaseChain = chains.create(
                policy=chain_policy,
                id=int(chain_id),
                magic=self.binout(magic),
                name=chain_name,
                code3=chain_code3,
                address_version=self.binout(address_version),
                script_addr_vers=self.binout(script_addr_vers),
                decimals=None if chain_decimals is None else int(chain_decimals),
            )

            # Legacy config option.
            if chain.name in no_bit8_chains and chain.has_feature(
                "block_version_bit8_merge_mine"
            ):
                chain = chains.create("LegacyNoBit8", chain)

            self.chains_by.id[chain.id] = chain
            self.chains_by.name[chain.name] = chain
            self.chains_by.magic[chain.magic] = chain

    def get_chain_by_id(self, chain_id: int) -> BaseChain:
        """get_chain_by_id"""
        return self.chains_by.id[chain_id]

    def get_chain_by_magic(self, magic: bytes) -> BaseChain:
        """get_chain_by_name"""
        return self.chains_by.magic.get(magic)

    def get_chain_by_name(self, name: str) -> BaseChain:
        """get_chain_by_name"""
        return self.chains_by.name.get(name)

    def get_default_chain(self) -> BaseChain:
        """get_default_chain"""
        self.log.debug("Falling back to default (Bitcoin) policy.")
        return chains.create(self.default_chain)

    def get_ddl(self, key):
        """get_ddl"""
        return self._ddl[key]

    def refresh_ddl(self):
        """refresh_ddl"""
        self._ddl = {
            "chain_summary": sql.CHAIN_SUMMARY,
            "txout_detail": sql.TXOUT_DETAIL,
            "txin_detail": sql.txin_detail(self.keep_scriptsig),
            "txout_approx": sql.TXOUT_APPROX,
            "configvar": sql.CONFIGVAR,
            "abe_sequences": sql.ABE_SEQUENCES,
        }

    def initialize(self):
        """
        Create the database schema.
        """
        self.config = {}
        self.configure()

        for stmt in (
            self._ddl["configvar"],
            sql.DATADIR,
            sql.BLOCK,
            sql.CHAIN,
            sql.CHAIN_CANDIDATE,
            sql.X_CC_BLOCK,
            sql.X_CC_CHAIN_BLOCK_HEIGHT,
            sql.X_CC_BLOCK_HEIGHT,
            sql.ORPHAN_BLOCK,
            sql.X_ORPHAN_BLOCK_HASHPREV,
            sql.BLOCK_NEXT,
            sql.TX,
            sql.UNLINKED_TX,
            sql.BLOCK_TX,
            sql.X_BLOCK_TX_TX,
            sql.PUBKEY,
            sql.MULTISIG_PUBKEY,
            sql.X_MULTISIG_PUBKEY_PUBKEY,
            sql.TXOUT,
            sql.X_TXOUT_PUBKEY,
            sql.txin(self.keep_scriptsig),
            sql.X_TXIN_TXOUT,
            sql.UNLINKED_TXIN,
            sql.X_UNLINKED_TXIN_OUTPUT,
            sql.BLOCK_TXIN,
            self._ddl["chain_summary"],
            self._ddl["txout_detail"],
            self._ddl["txin_detail"],
            self._ddl["txout_approx"],
            sql.ABE_LOCK,
        ):
            try:
                self.ddl(stmt)
            except Exception:
                self.log.error("Failed: %s", stmt)
                raise

        for key in ["chain", "datadir", "tx", "txout", "pubkey", "txin", "block"]:
            self.create_sequence(key)

        self.sql("INSERT INTO abe_lock (lock_id) VALUES (1)")

        # Insert some well-known chain metadata.
        for conf in CHAIN_CONFIG:
            conf = conf.copy()
            name = conf["chain"]
            chain = chains.create(name)
            self.insert_chain(chain)

        self.sql(
            """INSERT INTO pubkey (pubkey_id, pubkey_hash) VALUES (?, ?)""",
            (NULL_PUBKEY_ID, self.binin(NULL_PUBKEY_HASH)),
        )

        if self.args.use_firstbits:
            self.config["use_firstbits"] = "true"
            self.ddl(sql.ABE_FIRSTBITS)
            self.ddl(sql.X_ABE_FIRSTBITS)
        else:
            self.config["use_firstbits"] = "false"

        self.config["keep_scriptsig"] = "true" if self.args.keep_scriptsig else "false"

        self.save_config()
        self.commit()

    def insert_chain(self, chain):
        """insert_chain"""
        chain.id = self.new_id("chain")
        self.sql(
            """
            INSERT INTO chain (
                chain_id, chain_magic, chain_name, chain_code3,
                chain_address_version, chain_script_addr_vers, chain_policy, chain_decimals
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                chain.id,
                self.binin(chain.magic),
                chain.name,
                chain.code3,
                self.binin(chain.address_version),
                self.binin(chain.script_addr_vers),
                chain.policy,
                chain.decimals,
            ),
        )

    def get_lock(self):
        """get_lock"""
        if self.version_below("Abe26"):
            return None
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(f"UPDATE abe_lock SET pid = {os.getpid()} WHERE lock_id = 1")
        if cur.rowcount != 1:
            raise Exception("unexpected rowcount")
        cur.close()

        # Check whether database supports concurrent updates.  Where it
        # doesn't (SQLite) we get exclusive access automatically.
        try:

            letters = "".join([chr(randint(65, 90)) for x in range(10)])
            self.sql(
                """
                INSERT INTO configvar (configvar_name, configvar_value)
                VALUES (?, ?)""",
                ("upgrade-lock-" + letters, "x"),
            )
        except Exception:
            self.release_lock(conn)
            conn = None

        self.rollback()

        # XXX Should reread config.

        return conn

    def release_lock(self, conn):
        """release_lock"""
        if conn:
            conn.rollback()
            conn.close()

    def version_below(self, vers):
        """version_below"""
        try:
            schema_version = float(
                self.config["schema_version"].replace(SCHEMA_TYPE, "")
            )
        except ValueError:
            return False
        vers = float(vers.replace(SCHEMA_TYPE, ""))
        return schema_version < vers

    def configure(self):
        """configure"""
        config = self._sql.configure()
        self.init_binfuncs()
        for name in config.keys():
            self.config["sql." + name] = config[name]

    def save_config(self):
        """save_config"""
        self.config["schema_version"] = SCHEMA_VERSION
        for name in self.config.keys():
            self.save_configvar(name)

    def save_configvar(self, name):
        """save_configvar"""
        self.sql(
            "UPDATE configvar SET configvar_value = ?" " WHERE configvar_name = ?",
            (self.config[name], name),
        )
        if self.rowcount() == 0:
            self.sql(
                "INSERT INTO configvar (configvar_name, configvar_value)"
                " VALUES (?, ?)",
                (name, self.config[name]),
            )

    def set_configvar(self, name, value):
        """set_configvar"""
        self.config[name] = value
        self.save_configvar(name)

    def cache_block(self, block_id, height, prev_block_id, search_block_id) -> Block:
        """cache_block"""
        assert isinstance(block_id, int), repr(block_id)
        assert isinstance(height, int), repr(height)
        assert prev_block_id is None or isinstance(prev_block_id, int)
        assert search_block_id is None or isinstance(search_block_id, int)
        block: Block = {
            "height": height,
            "prev_block_id": prev_block_id,
            "search_block_id": search_block_id,
        }
        self._blocks[block_id] = block
        return block

    def _load_block(self, block_id) -> Optional[Block]:
        block: Block = self._blocks.get(block_id)
        if block is None:
            row = self.selectrow(
                """
                SELECT block_height, prev_block_id, search_block_id
                  FROM block
                 WHERE block_id = ?""",
                (block_id,),
            )
            if row is None:
                return None
            height, prev_block_id, search_block_id = row
            block = self.cache_block(
                block_id,
                int(height),
                None if prev_block_id is None else int(prev_block_id),
                None if search_block_id is None else int(search_block_id),
            )
        return block

    def get_block_id_at_height(
        self, height: Optional[int], descendant_id: Optional[int]
    ) -> Optional[int]:
        """get_block_id_at_height"""
        if height is None:
            return None

        while True:
            block = self._load_block(descendant_id)

            if block is None or block["height"] is None:
                raise LookupError

            if block["height"] == height:
                return descendant_id

            search_height = util.get_search_height(block["height"])
            descendant_id = block[
                "prev_block_id"  # type: ignore
                if search_height is None or search_height < height
                else "search_block_id"
            ]

    def is_descended_from(self, block_id, ancestor_id):
        """is_descended_from"""
        # ret = self._is_descended_from(block_id, ancestor_id)
        # self.log.debug("%d is%s descended from %d", block_id, '' if ret else ' NOT', ancestor_id)
        # return ret
        # def _is_descended_from(self, block_id, ancestor_id):
        block = self._load_block(block_id)
        ancestor = self._load_block(ancestor_id)
        height = ancestor["height"]
        return (
            block["height"] >= height
            and self.get_block_id_at_height(height, block_id) == ancestor_id
        )

    def get_block_height(self, block_id: int) -> Optional[int]:
        """get_block_height"""
        block: Optional[Block] = self._load_block(block_id)
        if block is None:
            return None
        return block["height"]

    def find_prev(
        self, _hash
    ) -> Tuple[
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
    ]:
        """find_prev"""
        row = self.selectrow(
            """
            SELECT block_id, block_height, block_chain_work,
                block_total_satoshis, block_total_seconds,
                block_satoshi_seconds, block_total_ss, block_nTime
            FROM block
            WHERE block_hash=?""",
            (self.hashin(_hash),),
        )
        if row is None:
            return (None, None, None, None, None, None, None, None)
        (
            block_id,
            height,
            chain_work,
            satoshis,
            seconds,
            satoshi_seconds,
            total_ss,
            nTime,
        ) = row
        return (
            int(block_id),
            None if height is None else int(height),
            self.binout_int(chain_work),
            None if satoshis is None else int(satoshis),
            None if seconds is None else int(seconds),
            None if satoshi_seconds is None else int(satoshi_seconds),
            None if total_ss is None else int(total_ss),
            int(nTime),
        )

    def import_block(self, block: Block, chain_ids=None, chain=None):
        """Import a block"""

        # Import new transactions.

        if chain_ids is None:
            chain_ids = frozenset() if chain is None else frozenset([chain.id])

        block["value_in"] = 0
        block["value_out"] = 0
        block["value_destroyed"] = 0
        tx_hash_array: List[bytes] = []

        # In the common case, all the block's txins _are_ linked, and we
        # can avoid a query if we notice this.
        all_txins_linked = True

        for pos, transaction in enumerate(block["transactions"]):
            if "hash" not in transaction:
                if chain is None:
                    self.log.debug("Falling back to SHA256 transaction hash")
                    transaction["hash"] = util.double_sha256(transaction["__data__"])
                else:
                    transaction["hash"] = chain.transaction_hash(
                        transaction["__data__"]
                    )

            tx_hash_array.append(transaction["hash"])
            transaction["tx_id"] = self.tx_find_id_and_value(transaction, pos == 0)

            if transaction["tx_id"]:
                all_txins_linked = False
            else:
                if self.commit_bytes == 0:
                    transaction["tx_id"] = self.import_and_commit_tx(
                        transaction, chain, pos == 0
                    )
                else:
                    transaction["tx_id"] = self.import_tx(transaction, chain, pos == 0)
                if transaction.get("unlinked_count", 1) > 0:
                    all_txins_linked = False

            if transaction["value_in"] is None:
                block["value_in"] = None
            elif block["value_in"] is not None:
                block["value_in"] += transaction["value_in"]

            block["value_out"] += transaction["value_out"]
            block["value_destroyed"] += transaction["value_destroyed"]

        # Get a new block ID.
        block_id: int = self.new_id("block")
        block["block_id"] = block_id

        if chain is not None:
            # Verify Merkle root.
            if block["hashMerkleRoot"] != Merkle(tx_hash_array).root():
                raise MerkleRootMismatch(block["hash"], tx_hash_array)

        # Look for the parent block.
        hashPrev: bytes = block["hashPrev"]

        is_genesis: bool = hashPrev == util.GENESIS_HASH_PREV

        (
            prev_block_id,
            prev_height,
            prev_work,
            prev_satoshis,
            prev_seconds,
            prev_ss,
            prev_total_ss,
            prev_nTime,
        ) = (
            (None, -1, 0, 0, 0, 0, 0, block["nTime"])
            if is_genesis
            else self.find_prev(hashPrev)
        )

        if prev_block_id is not None:
            block["prev_block_id"] = prev_block_id

        block["height"] = None if prev_height is None else prev_height + 1
        block["chain_work"] = util.calculate_work(prev_work, block["nBits"])

        if prev_seconds is None or prev_nTime is None:
            block["seconds"] = None
        else:
            block["seconds"] = prev_seconds + block["nTime"] - prev_nTime

        if prev_satoshis is None or prev_satoshis < 0 or block["value_in"] is None:
            # XXX Abuse this field to save work in adopt_orphans.
            block["satoshis"] = -1 - block["value_destroyed"]
        else:
            block["satoshis"] = (
                prev_satoshis
                + block["value_out"]
                - block["value_in"]
                - block["value_destroyed"]
            )

        if (
            prev_satoshis is None
            or prev_satoshis < 0
            or prev_nTime is None
            or prev_total_ss is None
        ):
            ss_created = None
            block["total_ss"] = None
        else:
            ss_created = prev_satoshis * (block["nTime"] - prev_nTime)
            block["total_ss"] = prev_total_ss + ss_created

        if block["height"] is None or block["height"] < 2:
            block["search_block_id"] = None
        else:
            block["search_block_id"] = self.get_block_id_at_height(
                util.get_search_height(block["height"]),
                None if prev_block_id is None else prev_block_id,
            )

        # Insert the block table row.
        try:
            self.sql(
                """INSERT INTO block (
                    block_id, block_hash, block_version, block_hashMerkleRoot,
                    block_nTime, block_nBits, block_nNonce, block_height,
                    prev_block_id, block_chain_work, block_value_in,
                    block_value_out, block_total_satoshis,
                    block_total_seconds, block_total_ss, block_num_tx,
                    search_block_id
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )""",
                (
                    block_id,
                    self.hashin(block["hash"]),
                    self.intin(block["version"]),
                    self.hashin(block["hashMerkleRoot"]),
                    self.intin(block["nTime"]),
                    self.intin(block["nBits"]),
                    self.intin(block["nNonce"]),
                    block["height"],
                    prev_block_id,
                    self.binin_int(block["chain_work"], WORK_BITS),
                    self.intin(block["value_in"]),
                    self.intin(block["value_out"]),
                    self.intin(block["satoshis"]),
                    self.intin(block["seconds"]),
                    self.intin(block["total_ss"]),
                    len(block["transactions"]),
                    block["search_block_id"],
                ),
            )

        except self.dbmodule.DatabaseError:

            if self.commit_bytes == 0:
                # Rollback won't undo any previous changes, since we
                # always commit.
                self.rollback()
                # If the exception is due to another process having
                # inserted the same block, it is okay.
                row = self.selectrow(
                    """
                    SELECT block_id, block_satoshi_seconds
                      FROM block
                     WHERE block_hash = ?""",
                    (self.hashin(block["hash"]),),
                )
                if row:
                    self.log.info(
                        "Block already inserted; block_id %d unsued", block_id
                    )
                    block["block_id"] = int(row[0])
                    block["ss"] = None if row[1] is None else int(row[1])
                    self.offer_block_to_chains(block, chain_ids)
                    return

            # This is not an expected error, or our caller may have to
            # rewind a block file.  Let them deal with it.
            raise

        # List the block's transactions in block_tx.
        for tx_pos in range(len(block["transactions"])):
            transaction = block["transactions"][tx_pos]
            self.sql("DELETE FROM unlinked_tx WHERE tx_id = ?", (transaction["tx_id"],))
            self.sql(
                """
                INSERT INTO block_tx
                    (block_id, tx_id, tx_pos)
                VALUES (?, ?, ?)""",
                (block_id, transaction["tx_id"], tx_pos),
            )
            self.log.info("block_tx %d %d", block_id, transaction["tx_id"])

        if block["height"] is not None:
            self._populate_block_txin(block_id)

            if all_txins_linked or not self._has_unlinked_txins(block_id):
                block["ss_destroyed"] = self._get_block_ss_destroyed(
                    block_id,
                    block["nTime"],
                    map(
                        lambda transaction: transaction["tx_id"], block["transactions"]
                    ),
                )
                if (
                    ss_created is None
                    or prev_ss is None
                    or block["ss_destroyed"] is None
                ):
                    block["ss"] = None
                else:
                    block["ss"] = prev_ss + ss_created - block["ss_destroyed"]

                self.sql(
                    """
                    UPDATE block
                       SET block_satoshi_seconds = ?,
                           block_ss_destroyed = ?
                     WHERE block_id = ?""",
                    (
                        self.intin(block["ss"]),
                        self.intin(block["ss_destroyed"]),
                        block_id,
                    ),
                )
            else:
                block["ss_destroyed"] = None
                block["ss"] = None

        # Store the inverse hashPrev relationship or mark the block as
        # an orphan.
        if prev_block_id:
            self.sql(
                """
                INSERT INTO block_next (block_id, next_block_id)
                VALUES (?, ?)""",
                (prev_block_id, block_id),
            )
        elif not is_genesis:
            self.sql(
                "INSERT INTO orphan_block (block_id, block_hashPrev)"
                + " VALUES (?, ?)",
                (block_id, self.hashin(block["hashPrev"])),
            )

        for row in self.selectall(
            """
            SELECT block_id FROM orphan_block WHERE block_hashPrev = ?""",
            (self.hashin(block["hash"]),),
        ):
            (orphan_id,) = row
            self.sql(
                "UPDATE block SET prev_block_id = ? WHERE block_id = ?",
                (block_id, orphan_id),
            )
            self.sql(
                """
                INSERT INTO block_next (block_id, next_block_id)
                VALUES (?, ?)""",
                (block_id, orphan_id),
            )
            self.sql("DELETE FROM orphan_block WHERE block_id = ?", (orphan_id,))

        # offer_block_to_chains calls adopt_orphans, which propagates
        # block_height and other cumulative data to the blocks
        # attached above.
        self.offer_block_to_chains(block, chain_ids)

        return block_id

    def _populate_block_txin(self, block_id):
        # Create rows in block_txin.  In case of duplicate transactions,
        # choose the one with the lowest block height.
        txin_oblocks = {}
        for txin_id, oblock_id in self.selectall(
            """
            SELECT txin.txin_id, obt.block_id
              FROM block_tx bt
              JOIN txin ON (txin.tx_id = bt.tx_id)
              JOIN txout ON (txin.txout_id = txout.txout_id)
              JOIN block_tx obt ON (txout.tx_id = obt.tx_id)
              JOIN block ob ON (obt.block_id = ob.block_id)
             WHERE bt.block_id = ?
               AND ob.block_chain_work IS NOT NULL
          ORDER BY txin.txin_id ASC, ob.block_height ASC""",
            (block_id,),
        ):

            # Save all candidate, lowest height might not be a descendant if
            # we have multiple block candidates
            txin_oblocks.setdefault(txin_id, []).append(oblock_id)

        for txin_id, oblock_ids in txin_oblocks.items():
            for oblock_id in oblock_ids:
                if self.is_descended_from(block_id, int(oblock_id)):
                    # Store lowest block height that is descended from our block
                    self.sql(
                        """
                        INSERT INTO block_txin (block_id, txin_id, out_block_id)
                        VALUES (?, ?, ?)""",
                        (block_id, txin_id, oblock_id),
                    )
                    break

    def _has_unlinked_txins(self, block_id):
        (unlinked_count,) = self.selectrow(
            """
            SELECT COUNT(1)
              FROM block_tx bt
              JOIN txin ON (bt.tx_id = txin.tx_id)
              JOIN unlinked_txin u ON (txin.txin_id = u.txin_id)
             WHERE bt.block_id = ?""",
            (block_id,),
        )
        return unlinked_count > 0

    def _get_block_ss_destroyed(self, block_id, nTime, tx_ids):
        block_ss_destroyed = 0
        for tx_id in tx_ids:
            destroyed = 0
            # Don't do the math in SQL as we risk losing precision
            for txout_value, block_nTime in self.selectall(
                """
                SELECT COALESCE(txout_approx.txout_approx_value, 0),
                       b.block_nTime
                  FROM block_txin bti
                  JOIN txin ON (bti.txin_id = txin.txin_id)
                  JOIN txout_approx ON (txin.txout_id = txout_approx.txout_id)
                  JOIN block_tx obt ON (txout_approx.tx_id = obt.tx_id)
                  JOIN block b ON (obt.block_id = b.block_id)
                 WHERE bti.block_id = ? AND txin.tx_id = ?""",
                (block_id, tx_id),
            ):
                destroyed += txout_value * (nTime - block_nTime)
            block_ss_destroyed += destroyed
        return block_ss_destroyed

    # Propagate cumulative values to descendant blocks.  Return info
    # about the longest chains containing b.  The returned dictionary
    # is keyed by the chain_id of a chain whose validation policy b
    # satisfies.  Each value is a pair (block, work) where block is
    # the best block descended from b in the given chain, and work is
    # the sum of orphan_work and the work between b and block.  Only
    # chains in chain_mask are considered.  Even if no known chain
    # contains b, this routine populates any descendant blocks'
    # cumulative statistics that are known for b and returns an empty
    # dictionary.
    def adopt_orphans(self, block, orphan_work, chain_ids, chain_mask):
        """adopt_orphans"""

        # XXX As originally written, this function occasionally hit
        # Python's recursion limit.  I am rewriting it iteratively
        # with minimal changes, hence the odd style.  Guido is
        # particularly unhelpful here, rejecting even labeled loops.

        ret = [None]

        def receive(val):
            ret[0] = val

        def doit():
            self._adopt_orphans_1(stack)

        stack = [receive, chain_mask, chain_ids, orphan_work, block, doit]
        while stack:
            stack.pop()()
        return ret[0]

    def _adopt_orphans_1(self, stack):
        def doit():
            self._adopt_orphans_1(stack)

        def continuation(val):
            self._adopt_orphans_2(stack, val)

        def didit():
            ret = stack.pop()
            stack.pop()(ret)

        block = stack.pop()
        orphan_work = stack.pop()
        chain_ids = stack.pop()
        chain_mask = stack.pop()
        ret = {}
        stack += [ret, didit]

        block_id = block["block_id"]
        height = None if block["height"] is None else int(block["height"] + 1)

        # If adding block b, b will not yet be in chain_candidate, so
        # we rely on the chain_ids argument.  If called recursively,
        # look up chain_ids in chain_candidate.
        if not chain_ids:
            if chain_mask:
                chain_mask = chain_mask.intersection(
                    self.find_chains_containing_block(block_id)
                )
            chain_ids = chain_mask

        for chain_id in chain_ids:
            ret[chain_id] = (block, orphan_work)

        for row in self.selectall(
            """
            SELECT bn.next_block_id, b.block_nBits,
                   b.block_value_out, b.block_value_in, b.block_nTime,
                   b.block_total_satoshis
              FROM block_next bn
              JOIN block b ON (bn.next_block_id = b.block_id)
             WHERE bn.block_id = ?""",
            (block_id,),
        ):
            next_id, nBits, value_out, value_in, nTime, satoshis = row
            nBits = int(nBits)
            nTime = int(nTime)
            satoshis = None if satoshis is None else int(satoshis)
            new_work = util.calculate_work(orphan_work, nBits)

            if block["chain_work"] is None:
                chain_work = None
            else:
                chain_work = block["chain_work"] + new_work - orphan_work

            if (
                value_in is None
            ):  # XXX getting a bunch of warnings in here during parsing
                value, count1, count2 = self.selectrow(
                    """
                    SELECT SUM(txout.txout_value),
                           COUNT(1),
                           COUNT(txout.txout_value)
                      FROM block_tx bt
                      JOIN txin ON (bt.tx_id = txin.tx_id)
                      LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
                     WHERE bt.block_id = ?""",
                    (next_id,),
                )
                if count1 == count2 + 1:
                    value_in = int(value)
                else:
                    self.log.warning(
                        "not updating block %d value_in: %s != %s + 1",
                        next_id,
                        repr(count1),
                        repr(count2),
                    )
            else:
                value_in = int(value_in)
            generated = None if value_in is None else int(value_out - value_in)

            if block["seconds"] is None:
                seconds = None
                total_ss = None
            else:
                new_seconds = nTime - block["nTime"]
                seconds = block["seconds"] + new_seconds
                if block["total_ss"] is None or block["satoshis"] is None:
                    total_ss = None
                else:
                    total_ss = block["total_ss"] + new_seconds * block["satoshis"]

            if (
                satoshis < 0
                and block["satoshis"] is not None
                and block["satoshis"] >= 0
                and generated is not None
            ):
                satoshis += 1 + block["satoshis"] + generated

            if height is None or height < 2:
                search_block_id = None
            else:
                search_block_id = self.get_block_id_at_height(
                    util.get_search_height(height), int(block_id)
                )

            self.sql(
                """
                UPDATE block
                   SET block_height = ?,
                       block_chain_work = ?,
                       block_value_in = ?,
                       block_total_seconds = ?,
                       block_total_satoshis = ?,
                       block_total_ss = ?,
                       search_block_id = ?
                 WHERE block_id = ?""",
                (
                    height,
                    self.binin_int(chain_work, WORK_BITS),
                    self.intin(value_in),
                    self.intin(seconds),
                    self.intin(satoshis),
                    self.intin(total_ss),
                    search_block_id,
                    next_id,
                ),
            )

            sat_sec = None

            if height is not None:
                self.sql(
                    """
                    UPDATE chain_candidate SET block_height = ?
                     WHERE block_id = ?""",
                    (height, next_id),
                )

                self._populate_block_txin(int(next_id))

                if block["ss"] is None or self._has_unlinked_txins(next_id):
                    pass
                else:
                    tx_ids = map(
                        lambda row: row[0],
                        self.selectall(
                            """
                            SELECT tx_id
                              FROM block_tx
                             WHERE block_id = ?""",
                            (next_id,),
                        ),
                    )
                    destroyed = self._get_block_ss_destroyed(next_id, nTime, tx_ids)
                    sat_sec = (
                        block["ss"]
                        + block["satoshis"] * (nTime - block["nTime"])
                        - destroyed
                    )

                    self.sql(
                        """
                        UPDATE block
                           SET block_satoshi_seconds = ?,
                               block_ss_destroyed = ?
                         WHERE block_id = ?""",
                        (self.intin(sat_sec), self.intin(destroyed), next_id),
                    )

                if self.use_firstbits:
                    for (addr_vers,) in self.selectall(
                        """
                        SELECT c.chain_address_version
                          FROM chain c
                          JOIN chain_candidate cc ON (c.chain_id = cc.chain_id)
                         WHERE cc.block_id = ?""",
                        (next_id,),
                    ):
                        self.do_vers_firstbits(addr_vers, int(next_id))

            new_block = {
                "block_id": next_id,
                "height": height,
                "chain_work": chain_work,
                "nTime": nTime,
                "seconds": seconds,
                "satoshis": satoshis,
                "total_ss": total_ss,
                "ss": sat_sec,
            }

            stack += [ret, continuation, chain_mask, None, new_work, new_block, doit]

    def _adopt_orphans_2(self, stack, next_ret):
        ret = stack.pop()
        for chain_id in ret.keys():
            pair = next_ret[chain_id]
            if pair and pair[1] > ret[chain_id][1]:
                ret[chain_id] = pair

    def _export_scriptPubKey(self, txout, chain: BaseChain, scriptPubKey):
        """In txout, set script_type, address_version, binaddr, and for multisig,
        required_signatures."""

        if scriptPubKey is None:
            txout["script_type"] = None
            txout["binaddr"] = None
            return

        script_type, data = chain.parse_txout_script(scriptPubKey)
        txout["script_type"] = script_type
        txout["address_version"] = chain.address_version

        if script_type == chains.SCRIPT_TYPE_PUBKEY:
            txout["binaddr"] = util.pubkey_to_hash(data)
        elif script_type == chains.SCRIPT_TYPE_ADDRESS:
            txout["binaddr"] = data
        elif script_type == chains.SCRIPT_TYPE_P2SH:
            txout["address_version"] = chain.script_addr_vers
            txout["binaddr"] = data
        elif script_type == chains.SCRIPT_TYPE_MULTISIG:
            txout["required_signatures"] = data["m"]
            txout["binaddr"] = util.pubkey_to_hash(scriptPubKey)
            txout["subbinaddr"] = [
                util.pubkey_to_hash(pubkey) for pubkey in data["pubkeys"]
            ]
        elif script_type == chains.SCRIPT_TYPE_BURN:
            txout["binaddr"] = NULL_PUBKEY_HASH
        else:
            txout["binaddr"] = None

    def export_block(
        self, chain: BaseChain = None, block_hash=None, block_number=None
    ) -> Optional[Dict[str, Any]]:
        """
        Return a dict with the following:

        * chain_candidates[]
            * chain
            * in_longest
        * chain_satoshis
        * chain_satoshi_seconds
        * chain_work
        * fees
        * generated
        * hash
        * hashMerkleRoot
        * hashPrev
        * height
        * nBits
        * next_block_hashes
        * nNonce
        * nTime
        * satoshis_destroyed
        * satoshi_seconds
        * transactions[]
            * fees
            * hash
            * in[]
                * address_version
                * binaddr
                * value
            * out[]
                * address_version
                * binaddr
                * value
            * size
        * value_out
        * version

        Additionally, for multisig inputs and outputs:

        * subbinaddr[]
        * required_signatures

        Additionally, for proof-of-stake chains:

        * is_proof_of_stake
        * proof_of_stake_generated
        """

        if block_number is None and block_hash is None:
            raise ValueError("export_block requires either block_hash or block_number")

        where = []
        bind = []

        if chain is not None:
            where.append("chain_id = ?")
            bind.append(chain.id)

        if block_hash is not None:
            where.append("block_hash = ?")
            bind.append(self.hashin_hex(block_hash))

        if block_number is not None:
            where.append("block_height = ? AND in_longest = 1")
            bind.append(block_number)

        _sql = f"""
            SELECT
                chain_id,
                in_longest,
                block_id,
                block_hash,
                block_version,
                block_hashMerkleRoot,
                block_nTime,
                block_nBits,
                block_nNonce,
                block_height,
                prev_block_hash,
                block_chain_work,
                block_value_in,
                block_value_out,
                block_total_satoshis,
                block_total_seconds,
                block_satoshi_seconds,
                block_total_ss,
                block_ss_destroyed,
                block_num_tx
              FROM chain_summary
             WHERE 
             AND {where}
             ORDER BY
                in_longest DESC,
                chain_id DESC"""
        rows = self.selectall(_sql, bind)

        if len(rows) == 0:
            return None

        row = rows[0][2:]

        def parse_cc(row):
            chain_id, in_longest = row[:2]
            return {"chain": self.get_chain_by_id(chain_id), "in_longest": in_longest}

        # Absent the chain argument, default to highest chain_id, preferring to avoid side chains.
        cc = map(parse_cc, rows)

        # "chain" may be None, but "found_chain" will not.
        found_chain = chain
        if found_chain is None:
            if len(cc) > 0:  # type: ignore
                found_chain = cc[0][  # type: ignore # pylint: disable=unsubscriptable-object
                    "chain"
                ]
            else:
                # Should not normally get here.
                found_chain = self.get_default_chain()

        (
            block_id,
            block_hash,
            block_version,
            hashMerkleRoot,
            nTime,
            nBits,
            nNonce,
            height,
            prev_block_hash,
            block_chain_work,
            _,  # value_in,
            _,  # value_out,
            satoshis,
            _,  # seconds,
            sat_sec,
            total_ss,
            destroyed,
            _,  # num_tx,
        ) = (
            row[0],
            self.hashout_hex(row[1]),
            row[2],
            self.hashout_hex(row[3]),
            row[4],
            int(row[5]),
            row[6],
            row[7],
            self.hashout_hex(row[8]),
            self.binout_int(row[9]),
            int(row[10]),
            int(row[11]),
            None if row[12] is None else int(row[12]),
            None if row[13] is None else int(row[13]),
            None if row[14] is None else int(row[14]),
            None if row[15] is None else int(row[15]),
            None if row[16] is None else int(row[16]),
            int(row[17]),
        )

        next_hashes = [
            self.hashout_hex(_hash)
            for _hash, il in self.selectall(
                """
            SELECT DISTINCT n.block_hash, cc.in_longest
              FROM block_next bn
              JOIN block n ON (bn.next_block_id = n.block_id)
              JOIN chain_candidate cc ON (n.block_id = cc.block_id)
             WHERE bn.block_id = ?
             ORDER BY cc.in_longest DESC""",
                (block_id,),
            )
        ]

        tx_ids = []
        txs: Dict[str, Any] = {}
        block_out = 0
        block_in = 0

        for row in self.selectall(
            """
            SELECT tx_id, tx_hash, tx_size, txout_value, txout_scriptPubKey
              FROM txout_detail
             WHERE block_id = ?
             ORDER BY tx_pos, txout_pos
        """,
            (block_id,),
        ):
            tx_id, tx_hash, tx_size, txout_value, scriptPubKey = (
                row[0],
                row[1],
                row[2],
                int(row[3]),
                self.binout(row[4]),
            )
            transaction = txs.get(tx_id)
            if transaction is None:
                tx_ids.append(tx_id)
                txs[tx_id] = {
                    "hash": self.hashout_hex(tx_hash),
                    "total_out": 0,
                    "total_in": 0,
                    "out": [],
                    "in": [],
                    "size": int(tx_size),
                }
                transaction = txs[tx_id]
            transaction["total_out"] += txout_value
            block_out += txout_value

            txout = {"value": txout_value}
            self._export_scriptPubKey(txout, found_chain, scriptPubKey)
            transaction["out"].append(txout)

        for row in self.selectall(
            """
            SELECT tx_id, txin_value, txin_scriptPubKey
              FROM txin_detail
             WHERE block_id = ?
             ORDER BY tx_pos, txin_pos
        """,
            (block_id,),
        ):
            tx_id, txin_value, scriptPubKey = (
                row[0],
                0 if row[1] is None else int(row[1]),
                self.binout(row[2]),
            )
            transaction = txs.get(tx_id)
            if transaction is None:
                # Strange, inputs but no outputs?
                tx_ids.append(tx_id)
                tx_hash, tx_size = self.selectrow(
                    """
                    SELECT tx_hash, tx_size FROM tx WHERE tx_id = ?""",
                    (tx_id,),
                )
                txs[tx_id] = {
                    "hash": self.hashout_hex(tx_hash),
                    "total_out": 0,
                    "total_in": 0,
                    "out": [],
                    "in": [],
                    "size": int(tx_size),
                }
                transaction = txs[tx_id]
            transaction["total_in"] += txin_value
            block_in += txin_value

            txin = {"value": txin_value}
            self._export_scriptPubKey(txin, found_chain, scriptPubKey)
            transaction["in"].append(txin)

        generated = block_out - block_in
        coinbase_tx = txs[tx_ids[0]]
        coinbase_tx["fees"] = 0
        block_fees = coinbase_tx["total_out"] - generated

        block = {
            "chain_candidates": cc,
            "chain_satoshis": satoshis,
            "chain_satoshi_seconds": total_ss,
            "chain_work": block_chain_work,
            "fees": block_fees,
            "generated": generated,
            "hash": block_hash,
            "hashMerkleRoot": hashMerkleRoot,
            "hashPrev": prev_block_hash,
            "height": height,
            "nBits": nBits,
            "next_block_hashes": next_hashes,
            "nNonce": nNonce,
            "nTime": nTime,
            "satoshis_destroyed": destroyed,
            "satoshi_seconds": sat_sec,
            "transactions": [txs[tx_id] for tx_id in tx_ids],
            "value_out": block_out,
            "version": block_version,
        }

        is_stake_chain = chain is not None and chain.has_feature("nvc_proof_of_stake")
        if is_stake_chain:
            # Proof-of-stake display based loosely on CryptoManiac/novacoin and
            # http://nvc.cryptocoinexplorer.com.
            block["is_proof_of_stake"] = (
                len(tx_ids) > 1 and coinbase_tx["total_out"] == 0
            )

        for tx_id in tx_ids[1:]:
            transaction = txs[tx_id]
            transaction["fees"] = transaction["total_in"] - transaction["total_out"]

        if is_stake_chain and block["is_proof_of_stake"]:
            block["proof_of_stake_generated"] = -txs[tx_ids[1]]["fees"]
            txs[tx_ids[1]]["fees"] = 0
            block["fees"] += block["proof_of_stake_generated"]  # type: ignore

        return block

    def tx_find_id_and_value(self, transaction, is_coinbase, check_only=False):
        """tx_find_id_and_value"""
        # Attention: value_out/undestroyed much match what is calculated in
        # import_tx
        row = self.selectrow(
            """
            SELECT tx.tx_id, SUM(txout.txout_value), SUM(
              CASE WHEN txout.pubkey_id IS NOT NULL AND txout.pubkey_id <= 0
                   THEN 0 ELSE txout.txout_value END)
              FROM tx
              LEFT JOIN txout ON (tx.tx_id = txout.tx_id)
             WHERE tx_hash = ?
             GROUP BY tx.tx_id""",
            (self.hashin(transaction["hash"]),),
        )
        if row:
            if check_only:
                # Don't update transaction, saves a statement when all we care is
                # whenever tx_id is in store
                return row[0]

            tx_id, value_out, undestroyed = row
            value_out = 0 if value_out is None else int(value_out)
            undestroyed = 0 if undestroyed is None else int(undestroyed)
            count_in, value_in = self.selectrow(
                """
                SELECT COUNT(1), SUM(prevout.txout_value)
                  FROM txin
                  JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
                 WHERE txin.tx_id = ?""",
                (tx_id,),
            )
            if (count_in or 0) < len(transaction["txIn"]):
                value_in = 0 if is_coinbase else None
            transaction["value_in"] = None if value_in is None else int(value_in)
            transaction["value_out"] = value_out
            transaction["value_destroyed"] = value_out - undestroyed
            return tx_id

        return None

    def import_tx(self, transaction, chain: BaseChain, is_coinbase: bool):
        """import_tx"""
        tx_id = self.new_id("tx")
        dbhash = self.hashin(transaction["hash"])

        if "size" not in transaction:
            transaction["size"] = len(transaction["__data__"])

        self.sql(
            """
            INSERT INTO tx (tx_id, tx_hash, tx_version, tx_lockTime, tx_size)
            VALUES (?, ?, ?, ?, ?)""",
            (
                tx_id,
                dbhash,
                self.intin(transaction["version"]),
                self.intin(transaction["lockTime"]),
                transaction["size"],
            ),
        )
        # Always consider tx are unlinked until they are added to block_tx.
        # This is necessary as inserted tx can get committed to database
        # before the block itself
        self.sql("INSERT INTO unlinked_tx (tx_id) VALUES (?)", (tx_id,))

        # Import transaction outputs.
        transaction["value_out"] = 0
        transaction["value_destroyed"] = 0
        for pos in range(len(transaction["txOut"])):
            txout = transaction["txOut"][pos]
            transaction["value_out"] += txout["value"]
            txout_id: Optional[int] = self.new_id("txout")

            pubkey_id = self.script_to_pubkey_id(chain, txout["scriptPubKey"])
            # Attention: much match how tx_find_id_and_value gets undestroyed
            # value
            if pubkey_id is not None and pubkey_id <= 0:
                transaction["value_destroyed"] += txout["value"]

            self.sql(
                """
                INSERT INTO txout (
                    txout_id, tx_id, txout_pos, txout_value,
                    txout_scriptPubKey, pubkey_id
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    txout_id,
                    tx_id,
                    pos,
                    self.intin(txout["value"]),
                    self.binin(txout["scriptPubKey"]),
                    pubkey_id,
                ),
            )
            for row in self.selectall(
                """
                SELECT txin_id
                  FROM unlinked_txin
                 WHERE txout_tx_hash = ?
                   AND txout_pos = ?""",
                (dbhash, pos),
            ):
                (txin_id,) = row
                self.sql(
                    "UPDATE txin SET txout_id = ? WHERE txin_id = ?",
                    (txout_id, txin_id),
                )
                self.sql("DELETE FROM unlinked_txin WHERE txin_id = ?", (txin_id,))

        # Import transaction inputs.
        transaction["value_in"] = 0
        transaction["unlinked_count"] = 0
        for pos in range(len(transaction["txIn"])):
            txin = transaction["txIn"][pos]
            txin_id = self.new_id("txin")

            if is_coinbase:
                txout_id = None
            else:
                txout_id, value = self.lookup_txout(
                    txin["prevout_hash"], txin["prevout_n"]
                )
                if value is None:
                    transaction["value_in"] = None
                elif transaction["value_in"] is not None:
                    transaction["value_in"] += value

            self.sql(
                """
                INSERT INTO txin (
                    txin_id, tx_id, txin_pos, txout_id"""
                + (
                    """,
                    txin_scriptSig, txin_sequence"""
                    if self.keep_scriptsig
                    else ""
                )
                + """
                ) VALUES (?, ?, ?, ?"""
                + (", ?, ?" if self.keep_scriptsig else "")
                + """)""",
                (
                    txin_id,
                    tx_id,
                    pos,
                    txout_id,
                    self.binin(txin["scriptSig"]),
                    self.intin(txin["sequence"]),
                )
                if self.keep_scriptsig
                else (txin_id, tx_id, pos, txout_id),
            )
            if not is_coinbase and txout_id is None:
                transaction["unlinked_count"] += 1
                self.sql(
                    """
                    INSERT INTO unlinked_txin (
                        txin_id, txout_tx_hash, txout_pos
                    ) VALUES (?, ?, ?)""",
                    (
                        txin_id,
                        self.hashin(txin["prevout_hash"]),
                        self.intin(txin["prevout_n"]),
                    ),
                )

        # XXX Could populate PUBKEY.PUBKEY with txin scripts...
        # or leave that to an offline process.  Nothing in this program
        # requires them.
        return tx_id

    def import_and_commit_tx(self, transaction, chain: BaseChain, is_coinbase):
        """import_and_commit_tx"""
        try:
            tx_id = self.import_tx(transaction, chain, is_coinbase)
            self.commit()

        except self.dbmodule.DatabaseError:
            self.rollback()
            # Violation of tx_hash uniqueness?
            tx_id = self.tx_find_id_and_value(transaction, is_coinbase)
            if not tx_id:
                raise

        return tx_id

    def maybe_import_binary_tx(self, chain_name: str, binary_tx):
        """maybe_import_binary_tx"""
        if chain_name is None:
            chain: BaseChain = self.get_default_chain()
        else:
            chain = self.get_chain_by_name(chain_name)

        tx_hash = chain.transaction_hash(binary_tx)

        (count,) = self.selectrow(
            "SELECT COUNT(1) FROM tx WHERE tx_hash = ?", (self.hashin(tx_hash),)
        )

        if count == 0:
            transaction = chain.parse_transaction(binary_tx)
            transaction["hash"] = tx_hash
            self.import_tx(transaction, chain, chain.is_coinbase_tx(transaction))
            self.imported_bytes(transaction["size"])

    def export_tx(
        self, tx_id=None, tx_hash=None, decimals=8, fmt="api", chain: BaseChain = None
    ):
        """Return a dict as seen by /rawtx or None if not found."""

        # TODO: merge _export_tx_detail with export_tx.
        if fmt == "browser":
            return self._export_tx_detail(tx_hash, chain=chain)

        transaction: Dict[str, Any] = {}
        is_bin = fmt == "binary"

        if tx_id is not None:
            row = self.selectrow(
                """
                SELECT tx_hash, tx_version, tx_lockTime, tx_size
                  FROM tx
                 WHERE tx_id = ?
            """,
                (tx_id,),
            )
            if row is None:
                return None
            transaction["hash"] = self.hashout_hex(row[0])

        elif tx_hash is not None:
            row = self.selectrow(
                """
                SELECT tx_id, tx_version, tx_lockTime, tx_size
                  FROM tx
                 WHERE tx_hash = ?
            """,
                (self.hashin_hex(tx_hash),),
            )
            if row is None:
                return None
            transaction["hash"] = tx_hash[::-1] if is_bin else tx_hash
            tx_id = row[0]

        else:
            raise ValueError("export_tx requires either tx_id or tx_hash.")

        transaction["version" if is_bin else "ver"] = int(row[1])  # type: ignore
        transaction["lockTime" if is_bin else "lock_time"] = int(row[2])  # type: ignore
        transaction["size"] = int(row[3])

        txins: List[Dict[str, Any]] = []
        transaction["txIn" if is_bin else "in"] = txins  # type: ignore
        for row in self.selectall(
            """
            SELECT
                COALESCE(tx.tx_hash, uti.txout_tx_hash),
                COALESCE(txout.txout_pos, uti.txout_pos)"""
            + (
                """,
                txin_scriptSig,
                txin_sequence"""
                if self.keep_scriptsig
                else ""
            )
            + """
            FROM txin
            LEFT JOIN txout ON (txin.txout_id = txout.txout_id)
            LEFT JOIN tx ON (txout.tx_id = tx.tx_id)
            LEFT JOIN unlinked_txin uti ON (txin.txin_id = uti.txin_id)
            WHERE txin.tx_id = ?
            ORDER BY txin.txin_pos""",
            (tx_id,),
        ):
            prevout_hash = row[0]
            prevout_n = None if row[1] is None else int(row[1])
            if is_bin:
                txin = {
                    "prevout_hash": self.hashout(prevout_hash),
                    "prevout_n": prevout_n,
                }
            else:
                if prevout_hash is None:
                    prev_out = {
                        "hash": "0" * 64,  # XXX should store this?
                        "n": 0xFFFFFFFF,
                    }  # XXX should store this?
                else:
                    prev_out = {"hash": self.hashout_hex(prevout_hash), "n": prevout_n}
                txin = {"prev_out": prev_out}
            if self.keep_scriptsig:
                scriptSig = row[2]
                sequence = row[3]
                if is_bin:
                    txin["scriptSig"] = self.binout(scriptSig)
                else:
                    txin["raw_scriptSig"] = self.binout_hex(scriptSig)
                txin["sequence"] = None if sequence is None else int(sequence)
            txins.append(txin)

        txouts: List[Dict[str, Any]] = []
        transaction["txOut" if is_bin else "out"] = txouts
        for satoshis, scriptPubKey in self.selectall(
            """
            SELECT txout_value, txout_scriptPubKey
              FROM txout
             WHERE tx_id = ?
            ORDER BY txout_pos""",
            (tx_id,),
        ):

            if is_bin:
                txout = {
                    "value": int(satoshis),
                    "scriptPubKey": self.binout(scriptPubKey),
                }
            else:
                coin = 10 ** decimals
                satoshis = int(satoshis)
                integer = satoshis / coin
                frac = satoshis % coin
                txout = {
                    "value": ("%%d.%%0%dd" % (decimals,)) % (integer, frac),
                    "raw_scriptPubKey": self.binout_hex(scriptPubKey),
                }
            txouts.append(txout)

        if not is_bin:
            transaction["vin_sz"] = len(txins)
            transaction["vout_sz"] = len(txouts)

        return transaction

    def _export_tx_detail(self, tx_hash, chain):
        try:
            dbhash = self.hashin_hex(tx_hash)
        except TypeError as error:
            raise MalformedHash() from error

        row = self.selectrow(
            """
            SELECT tx_id, tx_version, tx_lockTime, tx_size
              FROM tx
             WHERE tx_hash = ?
        """,
            (dbhash,),
        )
        if row is None:
            return None

        tx_id = int(row[0])
        transaction = {
            "hash": tx_hash,
            "version": int(row[1]),
            "lockTime": int(row[2]),
            "size": int(row[3]),
        }

        def parse_tx_cc(row):
            return {
                "chain": self.get_chain_by_id(row[0]),
                "in_longest": int(row[1]),
                "block_nTime": int(row[2]),
                "block_height": None if row[3] is None else int(row[3]),
                "block_hash": self.hashout_hex(row[4]),
                "tx_pos": int(row[5]),
            }

        transaction["chain_candidates"] = map(
            parse_tx_cc,
            self.selectall(
                """
            SELECT cc.chain_id, cc.in_longest,
                   b.block_nTime, b.block_height, b.block_hash,
                   block_tx.tx_pos
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
             WHERE block_tx.tx_id = ?
             ORDER BY cc.chain_id, cc.in_longest DESC, b.block_hash
        """,
                (tx_id,),
            ),
        )

        if chain is None:
            if len(transaction["chain_candidates"]) > 0:
                chain = transaction["chain_candidates"][0]["chain"]
            else:
                chain = self.get_default_chain()

        def parse_row(row):
            pos, script, value, o_hash, o_pos = row[:5]
            script = self.binout(script)
            scriptPubKey = self.binout(row[5]) if len(row) > 5 else script

            ret = {
                "pos": int(pos),
                "binscript": script,
                "value": None if value is None else int(value),
                "o_hash": self.hashout_hex(o_hash),
                "o_pos": None if o_pos is None else int(o_pos),
            }
            self._export_scriptPubKey(ret, chain, scriptPubKey)

            return ret

        # XXX Unneeded outer join.
        transaction["in"] = map(
            parse_row,
            self.selectall(
                """
            SELECT
                txin.txin_pos"""
                + (
                    """,
                txin.txin_scriptSig"""
                    if self.keep_scriptsig
                    else """,
                NULL"""
                )
                + """,
                txout.txout_value,
                COALESCE(prevtx.tx_hash, u.txout_tx_hash),
                COALESCE(txout.txout_pos, u.txout_pos),
                txout.txout_scriptPubKey
              FROM txin
              LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
              LEFT JOIN tx prevtx ON (txout.tx_id = prevtx.tx_id)
              LEFT JOIN unlinked_txin u ON (u.txin_id = txin.txin_id)
             WHERE txin.tx_id = ?
             ORDER BY txin.txin_pos
        """,
                (tx_id,),
            ),
        )

        # XXX Only one outer join needed.
        transaction["out"] = map(
            parse_row,
            self.selectall(
                """
            SELECT
                txout.txout_pos,
                txout.txout_scriptPubKey,
                txout.txout_value,
                nexttx.tx_hash,
                txin.txin_pos
              FROM txout
              LEFT JOIN txin ON (txin.txout_id = txout.txout_id)
              LEFT JOIN tx nexttx ON (txin.tx_id = nexttx.tx_id)
             WHERE txout.tx_id = ?
             ORDER BY txout.txout_pos
        """,
                (tx_id,),
            ),
        )

        def sum_values(rows):
            ret = 0
            for row in rows:
                if row["value"] is None:
                    return None
                ret += row["value"]
            return ret

        transaction["value_in"] = sum_values(transaction["in"])
        transaction["value_out"] = sum_values(transaction["out"])

        return transaction

    def export_address_history(
        self, address, max_rows=-1, types=frozenset(["direct", "escrow"])
    ) -> Union[Dict[str, Any], None]:
        """export_address_history"""
        version, binaddr = util.decode_check_address(address)
        if binaddr is None:
            raise MalformedAddress("Invalid address")

        balance = {}
        received = {}
        sent = {}
        counts = [0, 0]
        _chains = []

        def adj_balance(txpoint):
            chain = txpoint["chain"]

            if chain.id not in balance:
                _chains.append(chain)
                balance[chain.id] = 0
                received[chain.id] = 0
                sent[chain.id] = 0

            if txpoint["type"] == "direct":
                value = txpoint["value"]
                balance[chain.id] += value
                if txpoint["is_out"]:
                    sent[chain.id] -= value
                else:
                    received[chain.id] += value
                counts[txpoint["is_out"]] += 1

        dbhash = self.binin(binaddr)
        txpoints: List[Dict[str, Any]] = []

        def parse_row(
            is_out,
            row_type,
            nTime,
            chain_id,
            height,
            blk_hash,
            tx_hash,
            pos,
            value,
            script=None,
        ) -> Dict[str, Any]:
            chain = self.get_chain_by_id(chain_id)
            txpoint = {
                "type": row_type,
                "is_out": int(is_out),
                "nTime": int(nTime),
                "chain": chain,
                "height": int(height),
                "blk_hash": self.hashout_hex(blk_hash),
                "tx_hash": self.hashout_hex(tx_hash),
                "pos": int(pos),
                "value": int(value),
            }
            if script is not None:
                self._export_scriptPubKey(txpoint, chain, self.binout(script))

            return txpoint

        def parse_direct_in(row):
            return parse_row(True, "direct", *row)

        def parse_direct_out(row):
            return parse_row(False, "direct", *row)

        def parse_escrow_in(row):
            return parse_row(True, "escrow", *row)

        def parse_escrow_out(row):
            return parse_row(False, "escrow", *row)

        def get_received(escrow):
            return self.selectall(
                """
                SELECT
                    b.block_nTime,
                    cc.chain_id,
                    b.block_height,
                    b.block_hash,
                    tx.tx_hash,
                    txin.txin_pos,
                    -prevout.txout_value"""
                + (
                    """,
                    prevout.txout_scriptPubKey"""
                    if escrow
                    else ""
                )
                + """
                  FROM chain_candidate cc
                  JOIN block b ON (b.block_id = cc.block_id)
                  JOIN block_tx ON (block_tx.block_id = b.block_id)
                  JOIN tx ON (tx.tx_id = block_tx.tx_id)
                  JOIN txin ON (txin.tx_id = tx.tx_id)
                  JOIN txout prevout ON (txin.txout_id = prevout.txout_id)"""
                + (
                    """
                  JOIN multisig_pubkey mp ON (mp.multisig_id = prevout.pubkey_id)"""
                    if escrow
                    else ""
                )
                + """
                  JOIN pubkey ON (pubkey.pubkey_id = """
                + ("mp" if escrow else "prevout")
                + """.pubkey_id)
                 WHERE pubkey.pubkey_hash = ?
                   AND cc.in_longest = 1"""
                + (
                    ""
                    if max_rows < 0
                    else """
                 LIMIT ?"""
                ),
                (dbhash,) if max_rows < 0 else (dbhash, max_rows + 1),
            )

        def get_sent(escrow):
            return self.selectall(
                """
                SELECT
                    b.block_nTime,
                    cc.chain_id,
                    b.block_height,
                    b.block_hash,
                    tx.tx_hash,
                    txout.txout_pos,
                    txout.txout_value"""
                + (
                    """,
                    txout.txout_scriptPubKey"""
                    if escrow
                    else ""
                )
                + """
                  FROM chain_candidate cc
                  JOIN block b ON (b.block_id = cc.block_id)
                  JOIN block_tx ON (block_tx.block_id = b.block_id)
                  JOIN tx ON (tx.tx_id = block_tx.tx_id)
                  JOIN txout ON (txout.tx_id = tx.tx_id)"""
                + (
                    """
                  JOIN multisig_pubkey mp ON (mp.multisig_id = txout.pubkey_id)"""
                    if escrow
                    else ""
                )
                + """
                  JOIN pubkey ON (pubkey.pubkey_id = """
                + ("mp" if escrow else "txout")
                + """.pubkey_id)
                 WHERE pubkey.pubkey_hash = ?
                   AND cc.in_longest = 1"""
                + (
                    ""
                    if max_rows < 0
                    else """
                 LIMIT ?"""
                ),
                (dbhash, max_rows + 1) if max_rows >= 0 else (dbhash,),
            )

        if "direct" in types:
            in_rows = get_received(False)
            if len(in_rows) > max_rows >= 0:
                return None  # XXX Could still show address basic data.
            txpoints += map(parse_direct_in, in_rows)

            out_rows = get_sent(False)
            if len(out_rows) > max_rows >= 0:
                return None
            txpoints += map(parse_direct_out, out_rows)

        if "escrow" in types:
            in_rows = get_received(True)
            if len(in_rows) > max_rows >= 0:
                return None
            txpoints += map(parse_escrow_in, in_rows)

            out_rows = get_sent(True)
            if len(out_rows) > max_rows >= 0:
                return None
            txpoints += map(parse_escrow_out, out_rows)

        txpoints.sort(
            key=lambda l: (l["nTime"], l["is_out"], l["height"], l["chain"].name)
        )

        for txpoint in txpoints:
            adj_balance(txpoint)

        hist = {
            "binaddr": binaddr,
            "version": version,
            "chains": _chains,
            "txpoints": txpoints,
            "balance": balance,
            "sent": sent,
            "received": received,
            "counts": counts,
        }

        # Show P2SH address components, if known.
        # XXX With some more work, we could find required_signatures.
        for (subbinaddr,) in self.selectall(
            """
            SELECT sub.pubkey_hash
              FROM multisig_pubkey mp
              JOIN pubkey top ON (mp.multisig_id = top.pubkey_id)
              JOIN pubkey sub ON (mp.pubkey_id = sub.pubkey_id)
             WHERE top.pubkey_hash = ?""",
            (dbhash,),
        ):
            if "subbinaddr" not in hist:
                hist["subbinaddr"] = []
            if isinstance(hist["subbinaddr"], List):
                hist["subbinaddr"].append(self.binout(subbinaddr))

        return hist

    # Called to indicate that the given block has the correct magic
    # number and policy for the given chains.  Updates CHAIN_CANDIDATE
    # and CHAIN.CHAIN_LAST_BLOCK_ID as appropriate.
    def offer_block_to_chains(self, block, chain_ids):
        """offer_block_to_chains"""
        block["top"] = self.adopt_orphans(block, 0, chain_ids, chain_ids)
        for chain_id in chain_ids:
            self._offer_block_to_chain(block, chain_id)

    def _offer_block_to_chain(self, block, chain_id):
        if block["chain_work"] is None:
            in_longest = 0
        else:
            # Do we produce a chain longer than the current chain?
            # Query whether the new block (or its tallest descendant)
            # beats the current chain_last_block_id.  Also check
            # whether the current best is our top, which indicates
            # this block is in longest; this can happen in database
            # repair scenarios.
            top = block["top"][chain_id][0]
            row = self.selectrow(
                """
                SELECT b.block_id, b.block_height, b.block_chain_work
                  FROM block b, chain c
                 WHERE c.chain_id = ?
                   AND b.block_id = c.chain_last_block_id""",
                (chain_id,),
            )
            if row:
                loser_id, loser_height, loser_work = row
                if (
                    loser_id != top["block_id"]
                    and self.binout_int(loser_work) >= top["chain_work"]
                ):
                    row = None
            if row:
                # New longest chain.
                in_longest = 1
                to_connect = []
                to_disconnect = []
                winner_id = top["block_id"]
                winner_height = top["height"]
                while loser_height > winner_height:
                    to_disconnect.insert(0, loser_id)
                    loser_id = self.get_prev_block_id(loser_id)
                    loser_height -= 1
                while winner_height > loser_height:
                    to_connect.insert(0, winner_id)
                    winner_id = self.get_prev_block_id(winner_id)
                    winner_height -= 1
                loser_height = None
                while loser_id != winner_id:
                    to_disconnect.insert(0, loser_id)
                    loser_id = self.get_prev_block_id(loser_id)
                    to_connect.insert(0, winner_id)
                    winner_id = self.get_prev_block_id(winner_id)
                    winner_height -= 1
                for block_id in to_disconnect:
                    self.disconnect_block(block_id, chain_id)
                for block_id in to_connect:
                    self.connect_block(block_id, chain_id)

            elif block["hashPrev"] == self.get_chain_by_id(chain_id).genesis_hash_prev:
                in_longest = 1  # Assume only one genesis block per chain.  XXX
            else:
                in_longest = 0

        self.sql(
            """
            INSERT INTO chain_candidate (
                chain_id, block_id, in_longest, block_height
            ) VALUES (?, ?, ?, ?)""",
            (chain_id, block["block_id"], in_longest, block["height"]),
        )

        if in_longest > 0:
            self.sql(
                """
                UPDATE chain
                   SET chain_last_block_id = ?
                 WHERE chain_id = ?""",
                (top["block_id"], chain_id),
            )

        if self.use_firstbits and block["height"] is not None:
            (addr_vers,) = self.selectrow(
                """
                SELECT chain_address_version
                  FROM chain
                 WHERE chain_id = ?""",
                (chain_id,),
            )
            self.do_vers_firstbits(addr_vers, block["block_id"])

    def offer_existing_block(self, _hash, chain_id):
        """offer_existing_blocks"""
        block_row = self.selectrow(
            """
            SELECT block_id, block_height, block_chain_work,
                   block_nTime, block_total_seconds,
                   block_total_satoshis, block_satoshi_seconds,
                   block_total_ss
              FROM block
             WHERE block_hash = ?
        """,
            (self.hashin(_hash),),
        )

        if not block_row:
            return False

        if chain_id is None:
            return True

        # Block header already seen.  Don't import the block,
        # but try to add it to the chain.

        block = {
            "block_id": block_row[0],
            "height": block_row[1],
            "chain_work": self.binout_int(block_row[2]),
            "nTime": block_row[3],
            "seconds": block_row[4],
            "satoshis": block_row[5],
            "ss": block_row[6],
            "total_ss": block_row[7],
        }

        if self.selectrow(
            """
            SELECT 1
              FROM chain_candidate
             WHERE block_id = ?
               AND chain_id = ?""",
            (block["block_id"], chain_id),
        ):
            self.log.info("block %d already in chain %d", block["block_id"], chain_id)
        else:
            if block["height"] == 0:
                block["hashPrev"] = self.get_chain_by_id(chain_id).genesis_hash_prev
            else:
                block["hashPrev"] = "dummy"  # Fool adopt_orphans.
            self.offer_block_to_chains(block, frozenset([chain_id]))

        return True

    def find_next_blocks(self, block_id):
        """find_next_blocks"""
        ret = []
        for row in self.selectall(
            "SELECT next_block_id FROM block_next WHERE block_id = ?", (block_id,)
        ):
            ret.append(row[0])
        return ret

    def find_chains_containing_block(self, block_id):
        """find_chains_containing_blocks"""
        ret = []
        for row in self.selectall(
            "SELECT chain_id FROM chain_candidate WHERE block_id = ?", (block_id,)
        ):
            ret.append(row[0])
        return frozenset(ret)

    def get_prev_block_id(self, block_id):
        """get_prev_block_id"""
        return self.selectrow(
            "SELECT prev_block_id FROM block WHERE block_id = ?", (block_id,)
        )[0]

    def disconnect_block(self, block_id, chain_id):
        """disconnect_block"""
        self.sql(
            """
            UPDATE chain_candidate
               SET in_longest = 0
             WHERE block_id = ? AND chain_id = ?""",
            (block_id, chain_id),
        )

    def connect_block(self, block_id, chain_id):
        """connect_block"""
        self.sql(
            """
            UPDATE chain_candidate
               SET in_longest = 1
             WHERE block_id = ? AND chain_id = ?""",
            (block_id, chain_id),
        )

    def lookup_txout(self, tx_hash, txout_pos):
        """lookup_txout"""
        row = self.selectrow(
            """
            SELECT txout.txout_id, txout.txout_value
              FROM txout, tx
             WHERE txout.tx_id = tx.tx_id
               AND tx.tx_hash = ?
               AND txout.txout_pos = ?""",
            (self.hashin(tx_hash), txout_pos),
        )
        return (None, None) if row is None else (row[0], int(row[1]))

    def script_to_pubkey_id(self, chain: BaseChain, script: bytes):
        """Extract address and script type from transaction output script."""
        script_type, data = chain.parse_txout_script(script)

        if script_type in (chains.SCRIPT_TYPE_ADDRESS, chains.SCRIPT_TYPE_P2SH):
            return self.pubkey_hash_to_id(data)

        if script_type == chains.SCRIPT_TYPE_PUBKEY:
            return self.pubkey_to_id(data)

        if script_type == chains.SCRIPT_TYPE_MULTISIG:
            script_hash = util.script_to_hash(script)
            multisig_id = self._pubkey_id(script_hash, script)

            if not self.selectrow(
                "SELECT 1 FROM multisig_pubkey WHERE multisig_id = ?", (multisig_id,)
            ):
                for pubkey in set(data["pubkeys"]):
                    pubkey_id = self.pubkey_to_id(pubkey)
                    self.sql(
                        """
                        INSERT INTO multisig_pubkey (multisig_id, pubkey_id)
                        VALUES (?, ?)""",
                        (multisig_id, pubkey_id),
                    )
            return multisig_id

        if script_type == chains.SCRIPT_TYPE_BURN:
            return PUBKEY_ID_NETWORK_FEE

        return None

    def pubkey_hash_to_id(self, pubkey_hash: bytes) -> int:
        """pubkey_hash_to_id"""
        return self._pubkey_id(pubkey_hash, None)

    def pubkey_to_id(self, pubkey: bytes) -> int:
        """pubkey_to_id"""
        pubkey_hash = util.pubkey_to_hash(pubkey)
        return self._pubkey_id(pubkey_hash, pubkey)

    def _pubkey_id(self, pubkey_hash: bytes, pubkey: Optional[bytes]) -> int:
        dbhash = self.binin(pubkey_hash)  # binin, not hashin for 160-bit
        row = self.selectrow(
            """
            SELECT pubkey_id
              FROM pubkey
             WHERE pubkey_hash = ?""",
            (dbhash,),
        )
        if row:
            return int(row[0])
        pubkey_id = self.new_id("pubkey")

        if pubkey is not None and len(pubkey) > MAX_PUBKEY:
            pubkey = None

        self.sql(
            """
            INSERT INTO pubkey (pubkey_id, pubkey_hash, pubkey)
            VALUES (?, ?, ?)""",
            (pubkey_id, dbhash, self.binin(pubkey)),
        )
        return pubkey_id

    def flush(self):
        """flush"""
        if self.bytes_since_commit > 0:
            self.commit()
            self.log.debug("commit")
            self.bytes_since_commit = 0

    def imported_bytes(self, size):
        """imported_bytes"""
        self.bytes_since_commit += size
        if self.bytes_since_commit >= self.commit_bytes:
            self.flush()

    def catch_up(self):
        """catch_up"""
        for dircfg in self.datadirs:
            try:
                loader = dircfg["loader"] or self.default_loader
                if loader == "blkfile":
                    self.catch_up_dir(dircfg)
                elif loader in ("rpc", "rpc,blkfile", "default"):
                    if not self.catch_up_rpc(dircfg):
                        if loader == "rpc":
                            raise IOError("RPC load failed")
                        self.log.debug("catch_up_rpc: abort")
                        self.catch_up_dir(dircfg)
                else:
                    raise IOError(f"Unknown datadir loader: {loader}")

                self.flush()

            except IOError:
                self.log.exception("Failed to catch up %s", dircfg)
                self.rollback()

    def catch_up_rpc(self, dircfg: Dict):
        """
        Load new blocks using RPC.  Requires running *coind supporting
        getblockhash, getblock with verbose=false, and optionally
        getrawmempool/getrawtransaction (to load mempool tx). Requires
        chain_id in the datadir table.
        """
        chain_id = dircfg["chain_id"]
        if chain_id is None:
            self.log.error("no chain_id")
            return False
        chain: BaseChain = self.get_chain_by_id(chain_id)

        conffile = dircfg.get("conf") or chain.datadir_conf_file_name
        conffile = os.path.join(dircfg["dirname"], conffile)
        try:
            with open(conffile, encoding="utf-8") as file:
                conf: Dict[str, Any] = dict(
                    [
                        line.strip().split("=", 1)  # type:ignore
                        if "=" in line
                        else (line.strip(), True)
                        for line in file
                        if line != "" and line[0] not in "#\r\n"
                    ]
                )
        except (OSError, IOError) as error:
            self.log.error("failed to load %s: %s", conffile, error)
            return False

        rpcuser = self.rpcuser
        rpcpassword = self.rpcpassword
        rpcconnect = conf.get("rpcconnect", "127.0.0.1")
        rpcport = conf.get("rpcport", chain.datadir_rpcport)
        url = f"http://{rpcconnect}:{str(rpcport)}/"
        util.install_rpcopener(url, rpcuser, rpcpassword)

        data_stream = BCDataStream()

        if self.rpc_load_mempool:
            # Cache tx imported from mempool, so we can avoid querying DB on each pass
            rows = self.selectall(
                """
                SELECT t.tx_hash
                 FROM unlinked_tx ut
                 JOIN tx t ON (ut.tx_id = t.tx_id)"""
            )
            self.mempool_tx = {self.hashout_hex(i[0]) for i in rows}  # type: ignore

        def rpc(func, *params):
            self.rpclog.info("RPC>> %s %s", func, params)
            # print(f"url: {url}, method: {func}")
            ret = util.jsonrpc(url, func, *params)

            if self.rpclog.isEnabledFor(logging.INFO):
                self.rpclog.info(
                    "RPC<< %s", re.sub(r"\[[^\]]{100,}\]", "[...]", str(ret))
                )
            return ret

        def get_blockhash(height):
            try:
                return rpc("getblockhash", height)
            except util.JsonrpcException as e:
                if e.code in (-1, -5, -8):
                    # Block number out of range...
                    #  -1 is legacy code (pre-10.0), generic error
                    #  -8 (RPC_INVALID_PARAMETER) first seen in bitcoind 10.x
                    #  -5 (RPC_NOT_FOUND): Been suggested in #bitcoin-dev as more appropriate
                    return None
                raise

        # Returns -1 on error, so we'll get 0 on empty chain
        height = self.get_block_number(chain.id) + 1

        def get_tx(rpc_tx_hash, chain: BaseChain):
            try:
                rpc_tx_hex = rpc("getrawtransaction", rpc_tx_hash)

            except util.JsonrpcException as e:
                if e.code != -5:  # -5: transaction not in index.
                    raise
                if height != 0:
                    return None

                # The genesis transaction is unavailable.  This is
                # normal.

                rpc_tx_hex = genesis_tx.get(rpc_tx_hash)
                if rpc_tx_hex is None:
                    self.log.error(
                        "genesis tx unavailable via RPC;" " see import-tx in abe.conf"
                    )
                    return None

            rpc_tx = hex2b(rpc_tx_hex)
            tx_hash = hex2b(rpc_tx_hash)[::-1]

            computed_tx_hash = chain.transaction_hash(rpc_tx)
            if tx_hash != computed_tx_hash:
                # raise InvalidBlock('transaction hash mismatch')
                self.log.warning(
                    "transaction hash mismatch: %r != %r", tx_hash, computed_tx_hash
                )

            transaction = chain.parse_transaction(rpc_tx)
            transaction["hash"] = tx_hash
            return transaction

        def first_new_block(height, next_hash):
            """Find the first new block."""

            while height > 0:
                _hash = get_blockhash(height - 1)

                if _hash is not None and (1,) == self.selectrow(
                    """
                    SELECT 1
                      FROM chain_candidate cc
                      JOIN block b ON (cc.block_id = b.block_id)
                     WHERE b.block_hash = ?
                       AND b.block_height IS NOT NULL
                       AND cc.chain_id = ?""",
                    (self.hashin_hex(str(_hash)), chain.id),
                ):
                    break

                next_hash = _hash
                height -= 1

            return (height, next_hash)

        def catch_up_mempool(height):
            # Next height check time
            height_chk = time.time() + 30

            while self.rpc_load_mempool:
                # Import the memory pool.
                mempool = rpc("getrawmempool")

                for rpc_tx_hash in mempool:
                    # Skip any TX imported from previous run
                    if rpc_tx_hash in self.mempool_tx:
                        continue

                    # Break loop if new block found
                    if height_chk < time.time():
                        rpc_hash = get_blockhash(height)
                        if rpc_hash:
                            return rpc_hash
                        height_chk = time.time() + 1

                    transaction = get_tx(rpc_tx_hash, chain)
                    if transaction is None:
                        # NB: On new blocks, older mempool tx are often missing
                        # This happens some other times too, just get over with
                        self.log.info("tx %s gone from mempool", rpc_tx_hash)
                        continue

                    # XXX Race condition in low isolation levels.
                    tx_id = self.tx_find_id_and_value(
                        transaction, False, check_only=True
                    )
                    if tx_id is None:
                        tx_id = self.import_tx(transaction, chain, False)
                        self.log.info("mempool tx %d", tx_id)
                        self.imported_bytes(transaction["size"])

                # Only need to reset+save mempool tx cache once at the end
                self.mempool_tx = set(mempool)

                # Clean all unlinked tx not still in mempool
                self.clean_unlinked_tx(self.mempool_tx)
                self.log.info("mempool load completed, starting over...")
                time.sleep(3)
            return None

        try:

            # Get block hash at height, and at the same time, test
            # bitcoind connectivity.
            try:
                next_hash = get_blockhash(height)
            except util.JsonrpcException as error:
                raise error
            except Exception as error:
                # Connectivity failure.
                self.log.error("RPC failed: %s", error)
                return False
            # Get the first new block (looking backward until hash match)
            height, next_hash = first_new_block(height, next_hash)

            # Import new blocks.
            rpc_hash = next_hash or get_blockhash(height)

            while rpc_hash is not None:
                _hash = hex2b(rpc_hash)[::-1]
                if self.offer_existing_block(_hash, chain.id):
                    rpc_hash = get_blockhash(height + 1)
                else:
                    # get full RPC block with "getblock <hash> False"
                    data_stream.write(hex2b(rpc("getblock", rpc_hash, False)))
                    block_hash = chain.ds_block_header_hash(data_stream)
                    block = chain.ds_parse_block(data_stream)
                    assert _hash == block_hash
                    block["hash"] = block_hash

                    self.import_block(block, chain=chain)
                    self.imported_bytes(data_stream.read_cursor)
                    data_stream.clear()
                    rpc_hash = get_blockhash(height + 1)

                height += 1

            rpc_hash = catch_up_mempool(height)
            # Also look backwards in case we end up on an orphan block.
            # NB: Call only when rpc_hash is not None, otherwise
            #     we'll override catch_up_mempool's behavior.
            if rpc_hash:
                height, rpc_hash = first_new_block(height, rpc_hash)

        except util.JsonrpcMethodNotFound as e:
            self.log.error("bitcoind %s not supported", e.method)
            return False

        except InvalidBlock as e:
            self.log.error("RPC data not understood: %s", e)
            return False

        return True

    # Load all blocks starting at the current file and offset.
    def catch_up_dir(self, dircfg):
        """catch_up_dir"""

        def open_blkfile(number):
            self._refresh_dircfg(dircfg)
            blkfile = {
                "stream": BCDataStream(),
                "name": self.blkfile_name(dircfg, number),
                "number": number,
            }

            try:
                file = open(blkfile["name"], "rb")
            except IOError as e:
                # Early bitcoind used blk0001.dat to blk9999.dat.
                # Now it uses blocks/blk00000.dat to blocks/blk99999.dat.
                # Abe starts by assuming the former scheme.  If we don't
                # find the expected file but do see blocks/blk00000.dat,
                # switch to the new scheme.  Record the switch by adding
                # 100000 to each file number, so for example, 100123 means
                # blocks/blk00123.dat but 123 still means blk0123.dat.
                if blkfile["number"] > 9999 or e.errno != errno.ENOENT:
                    raise
                new_number = 100000
                blkfile["name"] = self.blkfile_name(dircfg, new_number)
                file = open(blkfile["name"], "rb")
                blkfile["number"] = new_number

            try:
                blkfile["stream"].map_file(file, 0)
            except Exception:
                # mmap can fail on an empty file, but empty files are okay.
                file.seek(0, os.SEEK_END)
                if file.tell() == 0:
                    blkfile["stream"].input = ""
                    blkfile["stream"].read_cursor = 0
                else:
                    blkfile["stream"].map_file(file, 0)
            finally:
                file.close()
            self.log.info("Opened %s", blkfile["name"])
            return blkfile

        def try_close_file(data_stream):
            try:
                data_stream.close_file()
            except Exception as e:
                self.log.info("BCDataStream: close_file: %s", e)

        try:
            blkfile = open_blkfile(dircfg["blkfile_number"])
        except IOError as e:
            self.log.warning("Skipping datadir %s: %s", dircfg["dirname"], e)
            return

        while True:
            dircfg["blkfile_number"] = blkfile["number"]
            data_stream = blkfile["stream"]
            next_blkfile = None

            try:
                self.import_blkdat(dircfg, data_stream, blkfile["name"])
            except Exception:
                self.log.warning("Exception at %d", data_stream.read_cursor)
                try_close_file(data_stream)
                raise

            if next_blkfile is None:
                # Try another file.
                try:
                    next_blkfile = open_blkfile(dircfg["blkfile_number"] + 1)
                except IOError as e:
                    if e.errno != errno.ENOENT:
                        raise
                    # No more block files.
                    return
                except Exception as e:
                    if getattr(e, "errno", None) == errno.ENOMEM:
                        # Assume 32-bit address space exhaustion.
                        self.log.warning(
                            "Cannot allocate memory for next blockfile: "
                            "skipping safety check"
                        )
                        try_close_file(data_stream)
                        blkfile = open_blkfile(dircfg["blkfile_number"] + 1)
                        dircfg["blkfile_offset"] = 0
                        continue
                    raise
                finally:
                    if next_blkfile is None:
                        try_close_file(data_stream)

                # Load any data written to the last file since we checked.
                self.import_blkdat(dircfg, data_stream, blkfile["name"])

                # Continue with the new file.
                blkfile = next_blkfile

            try_close_file(data_stream)
            dircfg["blkfile_offset"] = 0

    # Load all blocks from the given data stream.
    def import_blkdat(
        self,
        dircfg: Dict[str, Any],
        data_stream: BCDataStream,
        filename: str = "[unknown]",
    ) -> None:
        """import_blkdat"""
        if data_stream.input is None:
            raise SerializationError(
                f"No data was read when importing block data from {filename}."
            )
        # have to read the input into memory use bytes to keep immutable
        data_stream.input = bytes(data_stream.input)  # type:ignore
        filenum = dircfg["blkfile_number"]
        data_stream.read_cursor = dircfg["blkfile_offset"]

        while filenum == dircfg["blkfile_number"]:
            if data_stream.read_cursor + 8 > len(data_stream.input):
                break

            offset = data_stream.read_cursor
            magic = data_stream.read_bytes(4)

            # Assume no real magic number starts with a NUL.
            if magic[0] == b"\0":
                if filenum > 99999 and magic == b"\0\0\0\0":
                    # As of Bitcoin 0.8, files often end with a NUL span.
                    data_stream.read_cursor = offset
                    break
                # Skip NUL bytes at block end.
                data_stream.read_cursor = offset
                while data_stream.read_cursor < len(data_stream.input):
                    size = min(len(data_stream.input) - data_stream.read_cursor, 1000)
                    data = data_stream.read_bytes(size).lstrip(b"\0")
                    if data != "":
                        data_stream.read_cursor -= len(data)
                        break
                self.log.info(
                    "Skipped %d NUL bytes at block end",
                    data_stream.read_cursor - offset,
                )
                continue

            # Assume blocks obey the respective policy if they get here.
            chain_id: int = dircfg["chain_id"]
            chain: BaseChain = self.get_chain_by_id(chain_id)

            if chain is None:
                chain = self.get_chain_by_magic(magic)

            if chain is None:
                self.log.warning(
                    "Chain not found for magic number %s in block file %s at"
                    " offset %d.",
                    b2hex(magic),
                    filename,
                    offset,
                )

                not_magic = magic
                # Read this file's initial magic number.
                magic = data_stream.input[0:4]

                if magic == not_magic:
                    data_stream.read_cursor = offset
                    break

                self.log.info("Scanning for initial magic number %s.", b2hex(magic))

                data_stream.read_cursor = offset
                offset = data_stream.input.find(magic, offset)  # type:ignore
                if offset == -1:
                    self.log.info("Magic number scan unsuccessful.")
                    break

                self.log.info(
                    "Skipped %d bytes in block file %s at offset %d.",
                    offset - data_stream.read_cursor,
                    filename,
                    data_stream.read_cursor,
                )

                data_stream.read_cursor = offset
                continue

            length = data_stream.read_int32()
            end = data_stream.read_cursor + length

            if end > len(data_stream.input):
                self.log.debug(
                    "incomplete block of length %d chain %d", length, chain.id
                )
                data_stream.read_cursor = offset
                break

            _hash = chain.ds_block_header_hash(data_stream)

            # XXX should decode target and check hash against it to
            # avoid loading garbage data.  But not for merged-mined or
            # CPU-mined chains that use different proof-of-work
            # algorithms.

            if not self.offer_existing_block(_hash, chain.id):
                block: Block = chain.ds_parse_block(data_stream)
                block["hash"] = _hash

                if (
                    self.log.isEnabledFor(logging.DEBUG)
                    and block["hashPrev"] == chain.genesis_hash_prev
                ):
                    try:
                        self.log.debug(
                            "Chain %d genesis tx: %s",
                            chain.id,
                            b2hex(block["transactions"][0]["__data__"]),
                        )
                    except Exception:
                        pass

                self.import_block(block, chain=chain)
                if data_stream.read_cursor != end:
                    self.log.debug(
                        "Skipped %d bytes at block end", end - data_stream.read_cursor
                    )

            data_stream.read_cursor = end

            self.bytes_since_commit += length
            if self.bytes_since_commit >= self.commit_bytes:
                self.save_blkfile_offset(dircfg, data_stream.read_cursor)
                self.flush()
                self._refresh_dircfg(dircfg)

        if data_stream.read_cursor != dircfg["blkfile_offset"]:
            self.save_blkfile_offset(dircfg, data_stream.read_cursor)

    def blkfile_name(self, dircfg, number=None):
        """blkfile_name"""
        if number is None:
            number = dircfg["blkfile_number"]
        if number > 9999:
            return os.path.join(
                dircfg["dirname"], "blocks", f"blk{(number - 100000):05}.dat"
            )
        return os.path.join(dircfg["dirname"], f"blk{number:04}.dat")

    def save_blkfile_offset(self, dircfg, offset):
        """save_blkfile_offset"""
        self.sql(
            """
            UPDATE datadir
               SET blkfile_number = ?,
                   blkfile_offset = ?
             WHERE datadir_id = ?""",
            (dircfg["blkfile_number"], self.intin(offset), dircfg["id"]),
        )
        if self.rowcount() == 0:
            self.sql(
                """
                INSERT INTO datadir (datadir_id, dirname, blkfile_number,
                    blkfile_offset, chain_id)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    dircfg["id"],
                    dircfg["dirname"],
                    dircfg["blkfile_number"],
                    self.intin(offset),
                    dircfg["chain_id"],
                ),
            )
        dircfg["blkfile_offset"] = offset

    def _refresh_dircfg(self, dircfg):
        row = self.selectrow(
            """
            SELECT blkfile_number, blkfile_offset
              FROM datadir
             WHERE dirname = ?""",
            (dircfg["dirname"],),
        )
        if row:
            number, offset = map(int, row)
            if number > dircfg["blkfile_number"] or (
                number == dircfg["blkfile_number"] and offset > dircfg["blkfile_offset"]
            ):
                dircfg["blkfile_number"] = number
                dircfg["blkfile_offset"] = offset

    def get_block_number(self, chain_id):
        """get_block_number"""
        row = self.selectrow(
            """
            SELECT block_height
              FROM chain_candidate
             WHERE chain_id = ?
               AND in_longest = 1
             ORDER BY block_height DESC
             LIMIT 1""",
            (chain_id,),
        )
        return int(row[0]) if row else -1

    def get_target(self, chain_id):
        """get_target"""
        rows = self.selectall(
            """
            SELECT b.block_nBits
              FROM block b
              JOIN chain c ON (b.block_id = c.chain_last_block_id)
             WHERE c.chain_id = ?""",
            (chain_id,),
        )
        return util.calculate_target(int(rows[0][0])) if rows else None

    def get_received_and_last_block_id(self, chain_id, pubkey_hash, block_height=None):
        """get_received_and_last_block_id"""
        _sql = (
            """
            SELECT COALESCE(value_sum, 0), c.chain_last_block_id
              FROM chain c LEFT JOIN (
              SELECT cc.chain_id, SUM(txout.txout_value) value_sum
              FROM pubkey
              JOIN txout              ON (txout.pubkey_id = pubkey.pubkey_id)
              JOIN block_tx           ON (block_tx.tx_id = txout.tx_id)
              JOIN block b            ON (b.block_id = block_tx.block_id)
              JOIN chain_candidate cc ON (cc.block_id = b.block_id)
              WHERE
                  pubkey.pubkey_hash = ? AND
                  cc.chain_id = ? AND
                  cc.in_longest = 1"""
            + (
                ""
                if block_height is None
                else """ AND
                  cc.block_height <= ?"""
            )
            + """
              GROUP BY cc.chain_id
              ) a ON (c.chain_id = a.chain_id)
              WHERE c.chain_id = ?"""
        )
        dbhash = self.binin(pubkey_hash)

        return self.selectrow(
            _sql,
            (dbhash, chain_id, chain_id)
            if block_height is None
            else (dbhash, chain_id, block_height, chain_id),
        )

    def get_received(self, chain_id, pubkey_hash, block_height=None):
        """get_received"""
        return self.get_received_and_last_block_id(chain_id, pubkey_hash, block_height)[
            0
        ]

    def get_sent_and_last_block_id(self, chain_id, pubkey_hash, block_height=None):
        """get_sent_and_last_block_id"""
        _sql = (
            """
            SELECT COALESCE(value_sum, 0), c.chain_last_block_id
              FROM chain c LEFT JOIN (
              SELECT cc.chain_id, SUM(txout.txout_value) value_sum
              FROM pubkey
              JOIN txout              ON (txout.pubkey_id = pubkey.pubkey_id)
              JOIN txin               ON (txin.txout_id = txout.txout_id)
              JOIN block_tx           ON (block_tx.tx_id = txin.tx_id)
              JOIN block b            ON (b.block_id = block_tx.block_id)
              JOIN chain_candidate cc ON (cc.block_id = b.block_id)
              WHERE
                  pubkey.pubkey_hash = ? AND
                  cc.chain_id = ? AND
                  cc.in_longest = 1"""
            + (
                ""
                if block_height is None
                else """ AND
                  cc.block_height <= ?"""
            )
            + """
              GROUP BY cc.chain_id
              ) a ON (c.chain_id = a.chain_id)
              WHERE c.chain_id = ?"""
        )
        dbhash = self.binin(pubkey_hash)

        return self.selectrow(
            _sql,
            (dbhash, chain_id, chain_id)
            if block_height is None
            else (dbhash, chain_id, block_height, chain_id),
        )

    def get_sent(self, chain_id, pubkey_hash, block_height=None):
        """get_sent"""
        return self.get_sent_and_last_block_id(chain_id, pubkey_hash, block_height)[0]

    def get_balance(self, chain_id, pubkey_hash):
        """get_balance"""
        sent, last_block_id = self.get_sent_and_last_block_id(chain_id, pubkey_hash)
        received, last_block_id_2 = self.get_received_and_last_block_id(
            chain_id, pubkey_hash
        )

        # Deal with the race condition.
        for _ in range(2):
            if last_block_id == last_block_id_2:
                break

            self.log.debug(
                "Requerying balance: %d != %d", last_block_id, last_block_id_2
            )

            received, last_block_id_2 = self.get_received(
                chain_id, pubkey_hash, self.get_block_height(last_block_id)
            )

            if last_block_id == last_block_id_2:
                break

            self.log.info(
                "Balance query affected by reorg? %d != %d",
                last_block_id,
                last_block_id_2,
            )

            sent, last_block_id = self.get_sent(
                chain_id, pubkey_hash, self.get_block_height(last_block_id_2)
            )

        if last_block_id != last_block_id_2:
            self.log.warning("Balance query failed due to loader activity.")
            return None

        return received - sent

    def firstbits_full(self, version, _hash):
        """
        Return the address in lowercase.  An initial substring of this
        will become the firstbits.
        """
        return util.hash_to_address(version, _hash).lower()

    def insert_firstbits(self, pubkey_id, block_id, addr_vers, fb):
        """insert_firstbits"""
        self.sql(
            """
            INSERT INTO abe_firstbits (
                pubkey_id, block_id, address_version, firstbits
            )
            VALUES (?, ?, ?, ?)""",
            (pubkey_id, block_id, addr_vers, fb),
        )

    def cant_do_firstbits(self, addr_vers, block_id, pubkey_id):
        """cant_do_firstbits"""
        self.log.info(
            "No firstbits for pubkey_id %d, block_id %d, version '%s'",
            pubkey_id,
            block_id,
            self.binout_hex(addr_vers),
        )
        self.insert_firstbits(pubkey_id, block_id, addr_vers, "")

    def do_firstbits(self, addr_vers, block_id, fb, ids, full):
        """
        Insert the firstbits that start with fb using addr_vers and
        are first seen in block_id.  Return the count of rows
        inserted.

        fb -- string, not a firstbits using addr_vers in any ancestor
        of block_id
        ids -- set of ids of all pubkeys first seen in block_id whose
        firstbits start with fb
        full -- map from pubkey_id to full firstbits
        """

        if len(ids) <= 1:
            for pubkey_id in ids:
                self.insert_firstbits(pubkey_id, block_id, addr_vers, fb)
            return len(ids)

        pubkeys = {}
        for pubkey_id in ids:
            s = full[pubkey_id]
            if s == fb:
                self.cant_do_firstbits(addr_vers, block_id, pubkey_id)
                continue
            fb1 = fb + s[len(fb)]
            ids1 = pubkeys.get(fb1)
            if ids1 is None:
                ids1 = set()
                pubkeys[fb1] = ids1
            ids1.add(pubkey_id)

        count = 0
        for fb1, ids1 in enumerate(pubkeys):
            count += self.do_firstbits(addr_vers, block_id, fb1, ids1, full)
        return count

    def do_vers_firstbits(self, addr_vers, block_id):
        """
        Create new firstbits records for block and addr_vers.  All
        ancestor blocks must have their firstbits already recorded.
        """

        address_version = self.binout(addr_vers)
        pubkeys = {}  # firstbits to set of pubkey_id
        full = {}  # pubkey_id to full firstbits, or None if old

        for pubkey_id, pubkey_hash, oblock_id in self.selectall(
            """
            SELECT DISTINCT
                   pubkey.pubkey_id,
                   pubkey.pubkey_hash,
                   fb.block_id
              FROM block b
              JOIN block_tx bt ON (b.block_id = bt.block_id)
              JOIN txout ON (bt.tx_id = txout.tx_id)
              JOIN pubkey ON (txout.pubkey_id = pubkey.pubkey_id)
              LEFT JOIN abe_firstbits fb ON (
                       fb.address_version = ?
                   AND fb.pubkey_id = pubkey.pubkey_id)
             WHERE b.block_id = ?""",
            (addr_vers, block_id),
        ):

            pubkey_id = int(pubkey_id)

            if oblock_id is not None and self.is_descended_from(
                block_id, int(oblock_id)
            ):
                full[pubkey_id] = None

            if pubkey_id in full:
                continue

            full[pubkey_id] = self.firstbits_full(
                address_version, self.binout(pubkey_hash)
            )

        for pubkey_id, s in enumerate(full):
            if s is None:
                continue

            # This is the pubkey's first appearance in the chain.
            # Find the longest match among earlier firstbits.
            longest, longest_id = 0, None
            substrs = [s[0 : (i + 1)] for i in range(len(s))]
            for ancestor_id, fblen, o_pubkey_id in self.selectall(
                """
                SELECT block_id, LENGTH(firstbits), pubkey_id
                  FROM abe_firstbits fb
                 WHERE address_version = ?
                   AND firstbits IN (?"""
                + (",?" * (len(s) - 1))
                + """
                       )""",
                tuple([addr_vers] + substrs),
            ):
                if fblen > longest and self.is_descended_from(
                    block_id, int(ancestor_id)
                ):
                    longest, longest_id = fblen, o_pubkey_id

            # If necessary, extend the new fb to distinguish it from
            # the longest match.
            if longest_id is not None:
                (o_hash,) = self.selectrow(
                    "SELECT pubkey_hash FROM pubkey WHERE pubkey_id = ?", (longest_id,)
                )
                o_fb = self.firstbits_full(address_version, self.binout(o_hash))
                max_len = min(len(s), len(o_fb))
                while longest < max_len and s[longest] == o_fb[longest]:
                    longest += 1

            if longest == len(s):
                self.cant_do_firstbits(addr_vers, block_id, pubkey_id)
                continue

            fb = s[0 : (longest + 1)]
            ids = pubkeys.get(fb)
            if ids is None:
                ids = set()
                pubkeys[fb] = ids
            ids.add(pubkey_id)

        count = 0
        for fb, ids in enumerate(pubkeys):
            count += self.do_firstbits(addr_vers, block_id, fb, ids, full)
        return count

    def firstbits_to_addresses(self, fb, chain_id=None):
        """firstbits_to_addresses"""
        dbfb = fb.lower()
        ret = []
        bind = [fb[0 : (i + 1)] for i in range(len(fb))]
        if chain_id is not None:
            bind.append(chain_id)

        for dbhash, vers in self.selectall(
            """
            SELECT pubkey.pubkey_hash,
                   fb.address_version
              FROM abe_firstbits fb
              JOIN pubkey ON (fb.pubkey_id = pubkey.pubkey_id)
              JOIN chain_candidate cc ON (cc.block_id = fb.block_id)
             WHERE fb.firstbits IN (?"""
            + (",?" * (len(fb) - 1))
            + """)"""
            + (
                ""
                if chain_id is None
                else """
               AND cc.chain_id = ?"""
            ),
            tuple(bind),
        ):
            address = util.hash_to_address(self.binout(vers), self.binout(dbhash))
            if address.lower().startswith(dbfb):
                ret.append(address)

        if len(ret) == 0 or (len(ret) > 1 and fb in ret):
            ret = [fb]  # assume exact address match

        return ret

    def get_firstbits(self, address_version=None, db_pubkey_hash=None, chain_id=None):
        """
        Return address's firstbits, or the longest of multiple
        firstbits values if chain_id is not given, or None if address
        has not appeared, or the empty string if address has appeared
        but has no firstbits.
        """
        vers, dbhash = self.binin(address_version), db_pubkey_hash
        rows = self.selectall(
            """
            SELECT fb.firstbits
              FROM abe_firstbits fb
              JOIN pubkey ON (fb.pubkey_id = pubkey.pubkey_id)
              JOIN chain_candidate cc ON (fb.block_id = cc.block_id)
             WHERE cc.in_longest = 1
               AND fb.address_version = ?
               AND pubkey.pubkey_hash = ?"""
            + (
                ""
                if chain_id is None
                else """
               AND cc.chain_id = ?"""
            ),
            (vers, dbhash) if chain_id is None else (vers, dbhash, chain_id),
        )
        if not rows:
            return None

        ret = ""
        for (fb,) in rows:
            if len(fb) > len(ret):
                ret = fb
        return ret

    def clean_unlinked_tx(self, known_tx=None):
        """This method cleans up all unlinked tx'es found in table
        `unlinked_tx` except where the tx hash is provided in known_tx
        """

        rows = self.selectall(
            """
            SELECT ut.tx_id, t.tx_hash
             FROM unlinked_tx ut
             JOIN tx t ON (ut.tx_id = t.tx_id)"""
        )
        if not rows:
            return

        if not isinstance(known_tx, set):
            # convert list to set for faster lookups
            known_tx = set(known_tx)

        txcount = 0
        for tx_id, tx_hash in rows:
            if self.hashout_hex(tx_hash) in known_tx:
                continue

            self.log.debug("Removing unlinked tx: %r", tx_hash)
            self._clean_unlinked_tx(tx_id)
            txcount += 1

        if txcount:
            self.commit()
            self.log.info("Cleaned up %d unlinked transactions", txcount)
        else:
            self.log.info("No unlinked transactions to clean up")

    def _clean_unlinked_tx(self, tx_id):
        """Internal unlinked tx cleanup function, excluding the tracking table
        `unlinked_tx`. This function is required by upgrade.py.
        """

        # Clean up txin's
        unlinked_txins = self.selectall(
            """
            SELECT txin_id FROM txin
            WHERE tx_id = ?""",
            (tx_id,),
        )
        for txin_id in unlinked_txins:
            self.sql("DELETE FROM unlinked_txin WHERE txin_id = ?", (txin_id,))
        self.sql("DELETE FROM txin WHERE tx_id = ?", (tx_id,))

        # Clean up txouts & associated pupkeys ...
        txout_pubkeys = set(
            self.selectall(
                """
            SELECT pubkey_id FROM txout
            WHERE tx_id = ? AND pubkey_id IS NOT NULL""",
                (tx_id,),
            )
        )
        # Also add multisig pubkeys if any
        msig_pubkeys = set()
        for pk_id in txout_pubkeys:
            msig_pubkeys.update(
                self.selectall(
                    """
                SELECT pubkey_id FROM multisig_pubkey
                WHERE multisig_id = ?""",
                    (pk_id,),
                )
            )

        self.sql("DELETE FROM txout WHERE tx_id = ?", (tx_id,))

        # Now delete orphan pubkeys... For simplicity merge both sets together
        for pk_id in txout_pubkeys.union(msig_pubkeys):
            (count,) = self.selectrow(
                """
                SELECT COUNT(pubkey_id) FROM txout
                WHERE pubkey_id = ?""",
                (pk_id,),
            )
            if count == 0:
                self.sql("DELETE FROM multisig_pubkey WHERE multisig_id = ?", (pk_id,))
                (count,) = self.selectrow(
                    """
                    SELECT COUNT(pubkey_id) FROM multisig_pubkey
                    WHERE pubkey_id = ?""",
                    (pk_id,),
                )
                if count == 0:
                    self.sql("DELETE FROM pubkey WHERE pubkey_id = ?", (pk_id,))

        # Finally clean up tx itself
        self.sql("DELETE FROM unlinked_tx WHERE tx_id = ?", (tx_id,))
        self.sql("DELETE FROM tx WHERE tx_id = ?", (tx_id,))


def new(args) -> DataStore:
    """Instantiate a new DataStore"""
    return DataStore(args)


class CmdLine:
    """Command Line interface"""

    def __init__(self, argv, conf=None):
        self.argv = argv
        if conf is None:
            self.conf = {}
        else:
            self.conf = conf.copy()

    def usage(self):
        """usage"""
        return "Sorry, no help is available."

    def init(self) -> Tuple[Union[DataStore, None], Any]:
        """init"""

        self.conf.update({"debug": None, "logging": None})
        self.conf.update(CONFIG_DEFAULTS)

        args, argv = readconf.parse_argv(self.argv, self.conf, strict=False)
        if argv and argv[0] in ("-h", "--help"):
            print(self.usage())
            return None, []

        logging.basicConfig(
            stream=sys.stdout, level=logging.DEBUG, format="%(message)s"
        )
        if args.logging is not None:
            logging_config.dictConfig(args.logging)

        store = new(args)

        return store, argv
