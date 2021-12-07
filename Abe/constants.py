"""Constants used by multiple files """
# pylint: disable=unused-import
from typing import Any, Dict


MAX_SCRIPT = 1000000
MAX_PUBKEY = 65
NO_CLOB = "BUG_NO_CLOB"


SCHEMA_TYPE = "Abe"
SCHEMA_VERSION = SCHEMA_TYPE + "41"

CONFIG_DEFAULTS: Dict[str, Any] = {
    "dbtype": None,
    "connect_args": None,
    "binary_type": None,
    "int_type": None,
    "upgrade": None,
    "rescan": None,
    "commit_bytes": None,
    "log_sql": None,
    "log_rpc": None,
    "default_chain": "Bitcoin",
    "datadir": None,
    "ignore_bit8_chains": None,
    "use_firstbits": False,
    "keep_scriptsig": True,
    "import_tx": [],
    "default_loader": "default",
    "rpc_load_mempool": False,
    "rpcuser": None,
    "rpcpassword": None,
}

WORK_BITS = 304  # XXX more than necessary.

PUBKEY_HASH_LENGTH = 20
NULL_PUBKEY_HASH = b"\x00" * PUBKEY_HASH_LENGTH
NULL_PUBKEY_ID = 0
PUBKEY_ID_NETWORK_FEE = NULL_PUBKEY_ID
SCRIPT_NETWORK_FEE = NULL_PUBKEY_ID
