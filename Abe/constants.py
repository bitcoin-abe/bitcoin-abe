"""Constants used by multiple files """
# pylint: disable=unused-import
from .Chain import PUBKEY_HASH_LENGTH
from .SqlAbstraction import MAX_SCRIPT, MAX_PUBKEY, NO_CLOB


SCHEMA_TYPE = "Abe"
SCHEMA_VERSION = SCHEMA_TYPE + "41"

CONFIG_DEFAULTS = {
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

CHAIN_CONFIG = [
    {"chain": "Bitcoin"},
    {"chain": "Testnet"},
    # {"chain": "Namecoin"},
    # {
    #     "chain": "Weeds",
    #     "policy": "Sha256Chain",
    #     "code3": "WDS",
    #     "address_version": "\xf3",
    #     "magic": "\xf8\xbf\xb5\xda",
    # },
    # {
    #     "chain": "BeerTokens",
    #     "policy": "Sha256Chain",
    #     "code3": "BER",
    #     "address_version": "\xf2",
    #     "magic": "\xf7\xbf\xb5\xdb",
    # },
    # {
    #     "chain": "SolidCoin",
    #     "policy": "Sha256Chain",
    #     "code3": "SCN",
    #     "address_version": "\x7d",
    #     "magic": "\xde\xad\xba\xbe",
    # },
    # {
    #     "chain": "ScTestnet",
    #     "policy": "Sha256Chain",
    #     "code3": "SC0",
    #     "address_version": "\x6f",
    #     "magic": "\xca\xfe\xba\xbe",
    # },
    # {
    #     "chain": "Worldcoin",
    #     "policy": "Sha256Chain",
    #     "code3": "WDC",
    #     "address_version": "\x49",
    #     "magic": "\xfb\xc0\xb6\xdb",
    # },
    # {"chain": "NovaCoin"},
    # {"chain": "CryptoCash"},
    # {
    #     "chain": "Anoncoin",
    #     "policy": "Sha256Chain",
    #     "code3": "ANC",
    #     "address_version": "\x17",
    #     "magic": "\xFA\xCA\xBA\xDA",
    # },
    # {"chain": "Hirocoin"},
    # {"chain": "Bitleu"},
    # {"chain": "Maxcoin"},
    # {"chain": "Dash"},
    # {"chain": "BlackCoin"},
    # {"chain": "Unbreakablecoin"},
    # {"chain": "Californium"},
    # {"chain":"",
    # "code3":"", "address_version":"\x", "magic":""},
]

NULL_PUBKEY_HASH = "\0" * PUBKEY_HASH_LENGTH
NULL_PUBKEY_ID = 0
PUBKEY_ID_NETWORK_FEE = NULL_PUBKEY_ID
SCRIPT_NETWORK_FEE = NULL_PUBKEY_ID
