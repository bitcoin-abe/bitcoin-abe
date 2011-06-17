CREATE INDEX x_txout_pubkey ON txout (pubkey_id);
UPDATE config SET schema_version = '6'
 WHERE schema_version = '5' AND config_id = 1;
COMMIT;
