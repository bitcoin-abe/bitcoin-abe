/* Upgrade from Schema version 3 to 4. */

SELECT schema_version "THIS_HAD_BETTER_BE_3" FROM config WHERE config_id = 1;
SELECT 1 / (SELECT COUNT(1) FROM config WHERE config_id = 1 AND
       schema_version = '3') SHOULD_BE_1;

UPDATE config SET schema_version = '3.5' WHERE config_id = 1;

DROP VIEW chain_summary;
CREATE VIEW chain_summary AS SELECT
    cc.chain_id,
    cc.in_longest,
    block_id,
    b.block_hash,
    b.block_version,
    b.block_hashMerkleRoot,
    b.block_nTime,
    b.block_nBits,
    b.block_nNonce,
    b.block_height,
    b.prev_block_id,
    b.block_chain_work,
    COUNT(DISTINCT block_tx.tx_id) num_tx,
    SUM(txout.txout_value) value_out
FROM chain_candidate cc
JOIN block b USING (block_id)
JOIN block_tx USING (block_id)
JOIN txout USING (tx_id)
GROUP BY
    cc.chain_id,
    cc.in_longest,
    block_id,
    b.block_hash,
    b.block_version,
    b.block_hashMerkleRoot,
    b.block_nTime,
    b.block_nBits,
    b.block_nNonce,
    b.block_height,
    b.prev_block_id,
    b.block_chain_work;

UPDATE config SET schema_version = '4' WHERE config_id = 1;
COMMIT;
