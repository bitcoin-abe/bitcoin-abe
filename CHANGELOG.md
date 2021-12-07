# Bitcoin Abe Changelog

## New in 0.8 - ????

* Add support for Bitcoin Core up to v11.x in.

* Fix bug during upgrade to schema Abe30: add_keep_scriptsig.

* Fix bug affecting /rawtx.

* Add /unspent/ADDR|ADDR|... similar to blockchain.info/unspent?address=...

* Add support for MySQL binary types (also became default on newly-created databases).

* Add --rescan option.

* Add abe_loader tool to watch for and load new blocks.

* Add support for loading blocks using Bitcoin RPC

* Import unconfirmed transactions via RPC to bitcoind.

* Try to reconnect on stale db connection at transaction boundary.

* Crude SVG hash rate chart via nethash?format=svg.

* Increase maximum script length.

* Add /q/addressbalance.

* Don't mistake SQL syntax errors for idle timeouts.

* Try to get better error information after failure to read configvar.

* Doubled b58encode speed.

* Fix division-by-zero for truly zero-premine chains such as Doubloons.

* Support 32-byte pubkeys.

* Fix int-type detection for SQLite.

* Add Abe.admin CLI.

* Merge bitcointools upstream changes.

* Add --no-load option (webserver-only/skip load after --upgrade).

* Bug fix: KeyError: 'unlinked_count' in import_block.

* Fix string index out of range doing catch_up.

* Fix performance issue displaying large pages (page content returned as string, causing WSGIref to iterate over it).

* Support limited functionality without a database.

* Add Abe.abe --query option (cli for /q/COMMAND).

* Refactored external chains as independent objects.

* Add support for many external chains.

* Don't crash on page-not-found or chain-not-found.

* Fix block short links.

* Support P2SH and multisig addresses.

* Avoid crash on empty/short pubkey.

* Try reconnecting to database after disconnect.

* Fix SQLite large integers overflow.

* calculate_target: Return values closer to Bitcoin client.

* New options for external chains: --list-policies and --show-policy.

* Namecoin: don't crash on merge-mined block.

* Fix Abe always defaulting to NO_CLOB when creating database.

* Use ORDER BY instead of MAX() to get last block (Much faster at least on MySQL/TukuDB).

* Disable resolving of http client IP addresses which could slow down or hang Abe when client (proxy) is remote.

* Fix binary-type and int-type parameters being ignored in favor of auto-detection

* Fix issue where Crypto.Hash.RIPEMD was never being used (was using hashlib's workaround only)

## New in 0.7.2 - 2012-12-06

* Fixed bug affecting chains containing duplicate coinbase transactions.

## New in 0.7.1 - 2012-10-29

* Fixed bug affecting database upgrade.

## New in 0.7 - 2012-10-23

* Tell search engines not to crawl the whole chain.

* Raw transaction output in JSON format.

* Prevent denial of service via huge address history.

* Optional short addresses resembling Firstbits.

* Option to omit signature scripts for 20% space reduction.

* HTTP API function: getdifficulty.

* Work around failure to quit on Ctrl-C with SQLite.

* Report line number of errors in config file.

* Fixed bugs that cause wrong statistics when blocks arrive out of order.

* Minor fixes and updates.

## New in 0.6 - 2011-08-31

* Python packaging; abe.py moved; run as "python -m Abe.abe".

* Big speed improvements (c. 10x) for MySQL and SQLite.

* ODBC tested successfully.

* IBM DB2 tested successfully.

* HTTP API functions: getreceivedbyaddress getsentbyaddress.

* Verify transaction Merkle roots on block import.

* Show Namecoin-style network fees and name transaction outputs.

* Adjust coins outstanding and coin-days destroyed for Namecoin-style
  network fees.

* Native SolidCoin support.

* Suppress display of empty chains on home page.

* Show the search form on /chain/CHAIN pages.

* Many minor improvements; see the Git log.

## New in 0.5 - 2011-08-16

* Big speed improvement for address history and transaction pages.

* Big load time improvement for SQLite: below 10 hours for the BTC
  chain.

* MySQL supported.

* Oracle supported, but slow due to lack of transparent bind variable
  use in cx_Oracle.

* BBE-compatible HTTP API functions: nethash totalbc addresstohash
  hashtoaddress hashpubkey checkaddress

* New HTTP API functions: translate_address decode_address

* Online list of API functions (/q).

* Native BeerTokens currency support.

* Many minor improvements; see the Git log.

## New in 0.4.1 - 2011-08-16

* Security enhancement: refer to orphan blocks by hash, not height.

* Fixed bugs affecting new chains defined via the configuration.

* Warn, do not exit, if a block file is missing or unparsable.

* Abe parses the new merged-mining block field, CAuxPow.

* Decrement the value returned by getblockcount for compatibility.

* Bug fix: remove '-' from parenthesized amounts.

* Fixed previous/next block links on /chain/CHAIN/b/NUMBER pages.

* Accept "var += val" in configuration as equivalent to "var = val"
  where "var" has not been defined.

* Added --commit-bytes option to adjust the database commit interval.

* Minor robustness and cosmetic improvements.

## Major changes from 0.3 to 0.4 (2011-07-04 to 2011-07-15)

* The chain summary page (the one listing several blocks in the same
  chain) loads much faster than before.

* Address search accepts an initial substring, still without storing
  addresses in the database.

* FastCGI support has matured.  See README-FASTCGI.txt for setup.

* Abe supports Weeds currency natively.  Weeds info:
  <http://forum.bitcoin.org/index.php?topic=24209.0>

* The "datadir" configuration directive can add a new currency without
  changes to Python code.

* "auto-agpl" provides a link to download the source directory: a
  license compliance aid for those not wishing to use a Github fork.

* /chain/Bitcoin/q/getblockcount: first of (I hope) many
  BBE-compatible APIs.

* Several small fixes and speedups.
