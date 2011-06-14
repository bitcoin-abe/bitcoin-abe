/* Upgrade the ABE schema from Version 1 to Version 2.
   PostgreSQL --binary-type hex version.
   psql OPTS... < postgresql_hex_1_2.sql */

\set ON_ERROR_STOP 1

/* Make sure we are starting from the right version. */
SELECT 'Wrong schema configuration for this script, exiting' error
  FROM config WHERE config_id = 1 AND NOT
       (COALESCE(binary_type, '') = 'hex' AND
        COALESCE(schema_version, '') = '1');
/* Produce a divide-by-zero error to exit. */
SELECT 1 / (SELECT COUNT(1)
              FROM config
             WHERE config_id = 1
               AND binary_type = 'hex'
               AND schema_version = '1');

/* Set a temporary version string during upgrade. */
UPDATE config SET schema_version = '1.5' WHERE config_id = '1';

ALTER TABLE datadir RENAME COLUMN datadir TO dirname;

ALTER TABLE chain ADD COLUMN x_upgrade VARCHAR(200);
UPDATE chain SET x_upgrade =
    SUBSTRING('0123456789abcdef', chain_address_version::int/16 + 1, 1) ||
    SUBSTRING('0123456789abcdef', MOD(chain_address_version::int,16) + 1, 1);
ALTER TABLE chain ALTER COLUMN x_upgrade SET NOT NULL;
ALTER TABLE chain DROP COLUMN chain_address_version;
ALTER TABLE chain RENAME COLUMN x_upgrade TO chain_address_version;

UPDATE config SET schema_version = '2' WHERE config_id = '1';
COMMIT;
