/* Upgrade the ABE schema from Version 2 to Version 3.
   PostgreSQL version.
   psql OPTS... < postgresql_2_3.sql */

\set ON_ERROR_STOP 1

/* Make sure we are starting from the right version. */
SELECT 'Wrong schema configuration for this script, exiting' error
  FROM config WHERE config_id = 1 AND NOT
       (COALESCE(schema_version, '') = '2');
/* Produce a divide-by-zero error to exit. */
SELECT 1 / (SELECT COUNT(1)
              FROM config
             WHERE config_id = 1
               AND schema_version = '2') SHOULD_BE_1;

/* Set a temporary version string during upgrade. */
UPDATE config SET schema_version = '2.5' WHERE config_id = 1;

ALTER TABLE txout ADD COLUMN pubkey_id NUMERIC(26);
CREATE UNIQUE INDEX x_pubkey_txout_txout ON pubkey_txout (txout_id);
/* UPDATE txout SET pubkey_id = pt.pubkey_id FROM pubkey_txout pt
    WHERE txout.txout_id = pt.txout_id; */
UPDATE txout SET pubkey_id = (
    SELECT pubkey_id FROM pubkey_txout pt WHERE pt.txout_id = txout.txout_id);

DROP VIEW txin_detail;
CREATE VIEW txin_detail AS SELECT
    cc.chain_id,
    cc.in_longest,
    block_id,
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
    txin.txin_scriptSig,
    txin.txin_sequence,
    prevout.txout_value txin_value,
    pubkey.pubkey_id,
    pubkey.pubkey_hash,
    pubkey.pubkey
  FROM chain_candidate cc
  JOIN block b using (block_id)
  JOIN block_tx USING (block_id)
  JOIN tx    ON (tx.tx_id = block_tx.tx_id)
  JOIN txin  ON (tx.tx_id = txin.tx_id)
  LEFT JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
  LEFT JOIN pubkey
      ON (prevout.pubkey_id = pubkey.pubkey_id);

DROP VIEW txout_detail;
CREATE VIEW txout_detail AS SELECT
    cc.chain_id,
    cc.in_longest,
    block_id,
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
  JOIN block b using (block_id)
  JOIN block_tx USING (block_id)
  JOIN tx    ON (tx.tx_id = block_tx.tx_id)
  JOIN txout ON (tx.tx_id = txout.tx_id)
  LEFT JOIN pubkey USING (pubkey_id);

DROP TABLE pubkey_txout;

UPDATE config SET schema_version = '3' WHERE config_id = 1;
COMMIT;
