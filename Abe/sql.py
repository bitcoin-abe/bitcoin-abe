"""Library containing all of the long SQL statements"""
from constants import WORK_BITS, MAX_PUBKEY, MAX_SCRIPT

###############################################################################
# _ddl
###############################################################################
# I could do a lot with MATERIALIZED views.
CHAIN_SUMMARY = """
    CREATE OR REPLACE VIEW chain_summary AS SELECT
        cc.chain_id,
        cc.in_longest,
        b.block_id,
        b.block_hash,
        b.block_version,
        b.block_hashMerkleRoot,
        b.block_nTime,
        b.block_nBits,
        b.block_nNonce,
        cc.block_height,
        b.prev_block_id,
        prev.block_hash prev_block_hash,
        b.block_chain_work,
        b.block_num_tx,
        b.block_value_in,
        b.block_value_out,
        b.block_total_satoshis,
        b.block_total_seconds,
        b.block_satoshi_seconds,
        b.block_total_ss,
        b.block_ss_destroyed
    FROM chain_candidate cc
    JOIN block b ON (cc.block_id = b.block_id)
    LEFT JOIN block prev ON (b.prev_block_id = prev.block_id)"""

TXOUT_DETAIL = """
    CREATE OR REPLACE VIEW txout_detail AS SELECT
        cc.chain_id,
        cc.in_longest,
        cc.block_id,
        b.block_hash,
        b.block_height,
        block_tx.tx_pos,
        tx.tx_id,
        tx.tx_hash,
        tx.tx_lockTime,
        tx.tx_version,
        tx.tx_size,
        txout.txout_id,
        txout.txout_pos,
        txout.txout_value,
        txout.txout_scriptPubKey,
        pubkey.pubkey_id,
        pubkey.pubkey_hash,
        pubkey.pubkey
    FROM chain_candidate cc
    JOIN block b ON (cc.block_id = b.block_id)
    JOIN block_tx ON (b.block_id = block_tx.block_id)
    JOIN tx    ON (tx.tx_id = block_tx.tx_id)
    JOIN txout ON (tx.tx_id = txout.tx_id)
    LEFT JOIN pubkey ON (txout.pubkey_id = pubkey.pubkey_id)"""


def txin_detail(keep_scriptsig):
    """Returns the sql statement for txin_detail"""
    if keep_scriptsig:
        scriptsig = """ txin.txin_scriptSig, txin.txin_sequence"""

    else:
        scriptsig = """ NULL txin_scriptSig, NULL txin_sequence"""

    detail = f"""
        CREATE OR REPLACE VIEW txin_detail AS SELECT
            cc.chain_id,
            cc.in_longest,
            cc.block_id,
            b.block_hash,
            b.block_height,
            block_tx.tx_pos,
            tx.tx_id,
            tx.tx_hash,
            tx.tx_lockTime,
            tx.tx_version,
            tx.tx_size,
            txin.txin_id,
            txin.txin_pos,
            txin.txout_id prevout_id,
            {scriptsig},
            prevout.txout_value txin_value,
            prevout.txout_scriptPubKey txin_scriptPubKey,
            pubkey.pubkey_id,
            pubkey.pubkey_hash,
            pubkey.pubkey
        FROM chain_candidate cc
        JOIN block b ON (cc.block_id = b.block_id)
        JOIN block_tx ON (b.block_id = block_tx.block_id)
        JOIN tx    ON (tx.tx_id = block_tx.tx_id)
        JOIN txin  ON (tx.tx_id = txin.tx_id)
        LEFT JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
        LEFT JOIN pubkey ON (prevout.pubkey_id = pubkey.pubkey_id)"""
    return detail


# View of txout for drivers like sqlite3 that can not handle large
# integer arithmetic.  For them, we transform the definition of
# txout_approx_value to DOUBLE PRECISION (approximate) by a CAST.
TXOUT_APPROX = """
    CREATE OR REPLACE VIEW txout_approx AS SELECT
        txout_id,
        tx_id,
        txout_value txout_approx_value
    FROM txout"""

# ABE accounting.  This table is read without knowledge of the
# database's SQL quirks, so it must use only the most widely supported
# features.
CONFIGVAR = """
CREATE TABLE IF NOT EXISTS configvar (
    configvar_name  VARCHAR(100) NOT NULL PRIMARY KEY,
    configvar_value VARCHAR(255)
)"""

ABE_SEQUENCES = """CREATE TABLE IF NOT EXISTS abe_sequences (
    sequence_key VARCHAR(100) NOT NULL PRIMARY KEY,
    nextid NUMERIC(30)
)"""

###############################################################################
# Initialize
###############################################################################
DATADIR = """
    CREATE TABLE IF NOT EXISTS datadir (
        datadir_id  NUMERIC(10) NOT NULL PRIMARY KEY,
        dirname     VARCHAR(2000) NOT NULL,
        blkfile_number NUMERIC(8) NULL,
        blkfile_offset NUMERIC(20) NULL,
        chain_id    NUMERIC(10) NULL
    )"""

# A block of the type used by Bitcoin.
BLOCK = f"""
    CREATE TABLE IF NOT EXISTS block (
        block_id      NUMERIC(14) NOT NULL PRIMARY KEY,
        block_hash    BINARY(32)  UNIQUE NOT NULL,
        block_version NUMERIC(10),
        block_hashMerkleRoot BINARY(32),
        block_nTime   NUMERIC(20),
        block_nBits   NUMERIC(10),
        block_nNonce  NUMERIC(10),
        block_height  NUMERIC(14) NULL,
        prev_block_id NUMERIC(14) NULL,
        search_block_id NUMERIC(14) NULL,
        block_chain_work BINARY({str(int(WORK_BITS / 8))}),
        block_value_in NUMERIC(30) NULL,
        block_value_out NUMERIC(30),
        block_total_satoshis NUMERIC(26) NULL,
        block_total_seconds NUMERIC(20) NULL,
        block_satoshi_seconds NUMERIC(28) NULL,
        block_total_ss NUMERIC(28) NULL,
        block_num_tx  NUMERIC(10) NOT NULL,
        block_ss_destroyed NUMERIC(28) NULL,
        FOREIGN KEY (prev_block_id)
            REFERENCES block (block_id),
        FOREIGN KEY (search_block_id)
            REFERENCES block (block_id)
    )"""

# CHAIN comprises a magic number, a policy, and (indirectly via
# CHAIN_LAST_BLOCK_ID and the referenced block's ancestors) a genesis
# block, possibly null.  A chain may have a currency code.
CHAIN = """
    CREATE TABLE IF NOT EXISTS chain (
        chain_id    NUMERIC(10) NOT NULL PRIMARY KEY,
        chain_name  VARCHAR(100) UNIQUE NOT NULL,
        chain_code3 VARCHAR(5)  NULL,
        chain_address_version VARBINARY(100) NOT NULL,
        chain_script_addr_vers VARBINARY(100) NULL,
        chain_magic BINARY(4)     NULL,
        chain_policy VARCHAR(255) NOT NULL,
        chain_decimals NUMERIC(2) NULL,
        chain_last_block_id NUMERIC(14) NULL,
        FOREIGN KEY (chain_last_block_id)
            REFERENCES block (block_id)
    )"""

# CHAIN_CANDIDATE lists blocks that are, or might become, part of the
# given chain.  IN_LONGEST is 1 when the block is in the chain, else 0.
# IN_LONGEST denormalizes information stored canonically in
# CHAIN.CHAIN_LAST_BLOCK_ID and BLOCK.PREV_BLOCK_ID.
CHAIN_CANDIDATE = """
    CREATE TABLE IF NOT EXISTS chain_candidate (
        chain_id      NUMERIC(10) NOT NULL,
        block_id      NUMERIC(14) NOT NULL,
        in_longest    NUMERIC(1),
        block_height  NUMERIC(14),
        PRIMARY KEY (chain_id, block_id),
        FOREIGN KEY (block_id)
            REFERENCES block (block_id)
    )"""

X_CC_BLOCK = """CREATE INDEX IF NOT EXISTS x_cc_block ON chain_candidate (block_id)"""

X_CC_CHAIN_BLOCK_HEIGHT = """
    CREATE INDEX IF NOT EXISTS x_cc_chain_block_height
        ON chain_candidate (chain_id, block_height)"""

X_CC_BLOCK_HEIGHT = """
    CREATE INDEX IF NOT EXISTS x_cc_block_height ON chain_candidate (block_height)"""

# An orphan block must remember its hashPrev.
ORPHAN_BLOCK = """
    CREATE TABLE IF NOT EXISTS orphan_block (
        block_id      NUMERIC(14) NOT NULL PRIMARY KEY,
        block_hashPrev BINARY(32) NOT NULL,
        FOREIGN KEY (block_id) REFERENCES block (block_id)
    )"""

X_ORPHAN_BLOCK_HASHPREV = """
    CREATE INDEX IF NOT EXISTS x_orphan_block_hashPrev
        ON orphan_block (block_hashPrev)"""

# Denormalize the relationship inverse to BLOCK.PREV_BLOCK_ID.
BLOCK_NEXT = """
    CREATE TABLE IF NOT EXISTS block_next (
        block_id      NUMERIC(14) NOT NULL,
        next_block_id NUMERIC(14) NOT NULL,
        PRIMARY KEY (block_id, next_block_id),
        FOREIGN KEY (block_id) REFERENCES block (block_id),
        FOREIGN KEY (next_block_id) REFERENCES block (block_id)
    )"""

# A transaction of the type used by Bitcoin.
TX = """
    CREATE TABLE IF NOT EXISTS tx (
        tx_id         NUMERIC(26) NOT NULL PRIMARY KEY,
        tx_hash       BINARY(32)  UNIQUE NOT NULL,
        tx_version    NUMERIC(10),
        tx_lockTime   NUMERIC(10),
        tx_size       NUMERIC(10)
    )"""

# Mempool TX not linked to any block, we must track them somewhere
# for efficient cleanup
UNLINKED_TX = """
    CREATE TABLE IF NOT EXISTS unlinked_tx (
        tx_id        NUMERIC(26) NOT NULL,
        PRIMARY KEY (tx_id),
        FOREIGN KEY (tx_id)
            REFERENCES tx (tx_id)
    )"""

# Presence of transactions in blocks is many-to-many.
BLOCK_TX = """
    CREATE TABLE IF NOT EXISTS block_tx (
        block_id      NUMERIC(14) NOT NULL,
        tx_id         NUMERIC(26) NOT NULL,
        tx_pos        NUMERIC(10) NOT NULL,
        PRIMARY KEY (block_id, tx_id),
        UNIQUE (block_id, tx_pos),
        FOREIGN KEY (block_id)
            REFERENCES block (block_id),
        FOREIGN KEY (tx_id)
            REFERENCES tx (tx_id)
    )"""

X_BLOCK_TX_TX = """CREATE INDEX IF NOT EXISTS x_block_tx_tx ON block_tx (tx_id)"""

# A public key for sending bitcoins.  PUBKEY_HASH is derivable from a
# Bitcoin or Testnet address.
PUBKEY = f"""
    CREATE TABLE IF NOT EXISTS pubkey (
        pubkey_id     NUMERIC(26) NOT NULL PRIMARY KEY,
        pubkey_hash   BINARY(20)  UNIQUE NOT NULL,
        pubkey        VARBINARY({str(MAX_PUBKEY)}) NULL
    )"""

MULTISIG_PUBKEY = """
    CREATE TABLE IF NOT EXISTS multisig_pubkey (
        multisig_id   NUMERIC(26) NOT NULL,
        pubkey_id     NUMERIC(26) NOT NULL,
        PRIMARY KEY (multisig_id, pubkey_id),
        FOREIGN KEY (multisig_id) REFERENCES pubkey (pubkey_id),
        FOREIGN KEY (pubkey_id) REFERENCES pubkey (pubkey_id)
    )"""

X_MULTISIG_PUBKEY_PUBKEY = """
    CREATE INDEX IF NOT EXISTS x_multisig_pubkey_pubkey
        ON multisig_pubkey (pubkey_id)"""

# A transaction out-point.
TXOUT = f"""
    CREATE TABLE IF NOT EXISTS txout (
        txout_id      NUMERIC(26) NOT NULL PRIMARY KEY,
        tx_id         NUMERIC(26) NOT NULL,
        txout_pos     NUMERIC(10) NOT NULL,
        txout_value   NUMERIC(30) NOT NULL,
        txout_scriptPubKey VARBINARY({str(MAX_SCRIPT)}),
        pubkey_id     NUMERIC(26),
        UNIQUE (tx_id, txout_pos),
        FOREIGN KEY (pubkey_id)
            REFERENCES pubkey (pubkey_id)
    )"""

X_TXOUT_PUBKEY = """CREATE INDEX IF NOT EXISTS x_txout_pubkey ON txout (pubkey_id)"""
# A transaction in-point.
def txin(keep_scriptsig):
    """returns a sql statement for txin"""
    if keep_scriptsig:
        scriptsig = f"""txin_scriptSig VARBINARY({str(MAX_SCRIPT)}),
        txin_sequence NUMERIC(10),"""
    else:
        scriptsig = ""
    out = f"""
        CREATE TABLE IF NOT EXISTS txin (
            txin_id       NUMERIC(26) NOT NULL PRIMARY KEY,
            tx_id         NUMERIC(26) NOT NULL,
            txin_pos      NUMERIC(10) NOT NULL,
            txout_id      NUMERIC(26),
            {scriptsig}
            UNIQUE (tx_id, txin_pos),
            FOREIGN KEY (tx_id)
                REFERENCES tx (tx_id)
        )"""
    return out


X_TXIN_TXOUT = """CREATE INDEX IF NOT EXISTS x_txin_txout ON txin (txout_id)"""
# While TXIN.TXOUT_ID can not be found, we must remember TXOUT_POS,
# a.k.a. PREVOUT_N.

UNLINKED_TXIN = """
    CREATE TABLE IF NOT EXISTS unlinked_txin (
        txin_id       NUMERIC(26) NOT NULL PRIMARY KEY,
        txout_tx_hash BINARY(32)  NOT NULL,
        txout_pos     NUMERIC(10) NOT NULL,
        FOREIGN KEY (txin_id) REFERENCES txin (txin_id)
    )"""

X_UNLINKED_TXIN_OUTPUT = """
    CREATE INDEX IF NOT EXISTS x_unlinked_txin_outpoint
        ON unlinked_txin (txout_tx_hash, txout_pos)"""

BLOCK_TXIN = """
    CREATE TABLE IF NOT EXISTS block_txin (
        block_id      NUMERIC(14) NOT NULL,
        txin_id       NUMERIC(26) NOT NULL,
        out_block_id  NUMERIC(14) NOT NULL,
        PRIMARY KEY (block_id, txin_id),
        FOREIGN KEY (block_id) REFERENCES block (block_id),
        FOREIGN KEY (txin_id) REFERENCES txin (txin_id),
        FOREIGN KEY (out_block_id) REFERENCES block (block_id)
    )"""

ABE_LOCK = """
    CREATE TABLE IF NOT EXISTS abe_lock (
        lock_id       NUMERIC(10) NOT NULL PRIMARY KEY,
        pid           VARCHAR(255) NULL
    )"""

###########
# Only if firstbits is set
ABE_FIRSTBITS = """
    CREATE TABLE IF NO EXISTS abe_firstbits (
        pubkey_id       NUMERIC(26) NOT NULL,
        block_id        NUMERIC(14) NOT NULL,
        address_version VARBINARY(10) NOT NULL,
        firstbits       VARCHAR(50) NOT NULL,
        PRIMARY KEY (address_version, pubkey_id, block_id),
        FOREIGN KEY (pubkey_id) REFERENCES pubkey (pubkey_id),
        FOREIGN KEY (block_id) REFERENCES block (block_id)
    )"""

X_ABE_FIRSTBITS = """
    CREATE INDEX IF NOT EXISTS x_abe_firstbits
        ON abe_firstbits (address_version, firstbits)"""
