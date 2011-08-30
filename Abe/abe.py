#!/usr/bin/env python
# Copyright(C) 2011 by John Tobey <John.Tobey@gmail.com>

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

import sys
import os
import warnings
import optparse
import re
from cgi import escape
import posixpath
import wsgiref.util
import time
import binascii

import version
import DataStore
import readconf

# bitcointools -- modified deserialize.py to return raw transaction
import deserialize
import util  # Added functions.
import base58

__version__ = version.__version__

ABE_APPNAME = "Abe"
ABE_VERSION = __version__
ABE_URL = 'https://github.com/jtobey/bitcoin-abe'

COPYRIGHT_YEARS = '2011'
COPYRIGHT = "John Tobey"
COPYRIGHT_URL = "mailto:John.Tobey@gmail.com"

DONATIONS_BTC = '1PWC7PNHL1SgvZaN7xEtygenKjWobWsCuf'
DONATIONS_NMC = 'NJ3MSELK1cWnqUa6xhF2wUYAnz3RSrWXcK'

DEFAULT_TEMPLATE = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <link rel="stylesheet" type="text/css"
     href="%(dotdot)s%(STATIC_PATH)sabe.css" />
    <link rel="shortcut icon" href="%(dotdot)s%(STATIC_PATH)sfavicon.ico" />
    <title>%(title)s</title>
</head>
<body>
    <h1><a href="%(dotdot)schains"><img
     src="%(dotdot)s%(STATIC_PATH)slogo32.png" alt="Abe logo" /></a> %(h1)s
    </h1>
    %(body)s
    <p><a href="%(dotdot)sq">API</a> (machine-readable pages)</p>
    <p style="font-size: smaller">
        <span style="font-style: italic">
            <a href="%(ABE_URL)s">%(APPNAME)s</a>
            %(VERSION)s &#169; %(COPYRIGHT_YEARS)s
            <a href="%(COPYRIGHT_URL)s">%(COPYRIGHT)s</a>
        </span>
        %(download)s
        Tips appreciated!
        <a href="%(dotdot)saddress/%(DONATIONS_BTC)s">BTC</a>
        <a href="%(dotdot)saddress/%(DONATIONS_NMC)s">NMC</a>
    </p>
</body>
</html>
"""

# XXX This should probably be a property of chain, or even a query param.
LOG10COIN = 8
COIN = 10 ** LOG10COIN

ADDRESS_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{26,}\\Z')
# It is fun to change "6" to "3" and search lots of addresses.
ADDR_PREFIX_RE = re.compile('[1-9A-HJ-NP-Za-km-z]{6,}\\Z')
HEIGHT_RE = re.compile('(?:0|[1-9][0-9]*)\\Z')
HASH_PREFIX_RE = re.compile('[0-9a-fA-F]{6,64}\\Z')

NETHASH_HEADER = """\
blockNumber:          height of last block in interval + 1
time:                 block time in seconds since 0h00 1 Jan 1970 UTC
target:               decimal target at blockNumber
avgTargetSinceLast:   harmonic mean of target over interval
difficulty:           difficulty at blockNumber
hashesToWin:          expected number of hashes needed to solve a block at this difficulty
avgIntervalSinceLast: interval seconds divided by blocks
netHashPerSecond:     estimated network hash rate over interval

Statistical values are approximate and differ slightly from http://blockexplorer.com/q/nethash.

/chain/CHAIN/q/nethash[/INTERVAL[/START[/STOP]]]
Default INTERVAL=144, START=0, STOP=infinity.

blockNumber,time,target,avgTargetSinceLast,difficulty,hashesToWin,avgIntervalSinceLast,netHashPerSecond
START DATA
"""

def make_store(args):
    store = DataStore.new(args)
    store.catch_up()
    return store

class NoSuchChainError(Exception):
    """Thrown when a chain lookup fails"""

class PageNotFound(Exception):
    """Thrown when code wants to return 404 Not Found"""

class Redirect(Exception):
    """Thrown when code wants to redirect the request"""

class Streamed(Exception):
    """Thrown when code has written the document to the callable
    returned by start_response."""

class Abe:
    def __init__(abe, store, args):
        abe.store = store
        abe.args = args
        abe.htdocs = args.document_root or find_htdocs()
        abe.static_path = '' if args.static_path is None else args.static_path
        abe.template_vars = args.template_vars.copy()
        abe.template_vars['STATIC_PATH'] = (
            abe.template_vars.get('STATIC_PATH', abe.static_path))
        abe.template = flatten(args.template)
        abe.debug = args.debug
        import logging
        abe.log = logging
        abe.log.info('Abe initialized.')
        abe.home = "chains"
        if not args.auto_agpl:
            abe.template_vars['download'] = (
                abe.template_vars.get('download', ''))

    def __call__(abe, env, start_response):
        import urlparse

        status = '200 OK'
        page = {
            "title": [escape(ABE_APPNAME), " ", ABE_VERSION],
            "body": [],
            "env": env,
            "params": {},
            "dotdot": "../" * (env['PATH_INFO'].count('/') - 1),
            "start_response": start_response,
            "content_type": 'application/xhtml+xml',
            "template": abe.template,
            }
        if 'QUERY_STRING' in env:
            page['params'] = urlparse.parse_qs(env['QUERY_STRING'])

        if fix_path_info(env):
            print "fixed path_info"
            return redirect(page)

        cmd = wsgiref.util.shift_path_info(env)
        if cmd == '':
            cmd = abe.home
        handler = getattr(abe, 'handle_' + cmd, None)

        try:
            if handler is None:
                return abe.serve_static(cmd + env['PATH_INFO'], start_response)

            # Always be up-to-date, even if we means having to wait
            # for a response!  XXX Could use threads, timers, or a
            # cron job.
            abe.store.catch_up()

            handler(page)
        except PageNotFound:
            status = '404 Not Found'
            page["body"] = ['<p class="error">Sorry, ', env['SCRIPT_NAME'],
                            env['PATH_INFO'],
                            ' does not exist on this server.</p>']
        except NoSuchChainError, e:
            page['body'] += [
                '<p class="error">'
                'Sorry, I don\'t know about that chain!</p>\n']
        except Redirect:
            return redirect(page)
        except Streamed:
            return ''
        except:
            abe.store.rollback()
            raise

        abe.store.rollback()  # Close imlicitly opened transaction.

        start_response(status, [('Content-type', page['content_type']),
                                ('Cache-Control', 'max-age=30')])

        tvars = abe.template_vars.copy()
        tvars['dotdot'] = page['dotdot']
        tvars['title'] = flatten(page['title'])
        tvars['h1'] = flatten(page.get('h1') or page['title'])
        tvars['body'] = flatten(page['body'])
        if abe.args.auto_agpl:
            tvars['download'] = (
                ' <a href="' + page['dotdot'] + 'download">Source</a>')

        return page['template'] % tvars

    def handle_chains(abe, page):
        page['title'] = ABE_APPNAME + ' Search'
        body = page['body']
        body += [
            abe.search_form(page),
            '<table>\n',
            '<tr><th>Currency</th><th>Code</th><th>Block</th><th>Time</th>',
            '<th>Started</th><th>Age (days)</th><th>Coins Created</th>',
            '<th>Avg Coin Age</th><th>',
            '% <a href="https://en.bitcoin.it/wiki/Bitcoin_Days_Destroyed">',
            'CoinDD</a></th>',
            '</tr>\n']
        now = time.time()

        rows = abe.store.selectall("""
            SELECT c.chain_name, b.block_height, b.block_nTime,
                   b.block_total_seconds, b.block_total_satoshis,
                   b.block_satoshi_seconds, b.block_hash,
                   b.block_total_ss, c.chain_id, c.chain_code3,
                   c.chain_address_version, c.chain_last_block_id
              FROM chain c
              JOIN block b ON (c.chain_last_block_id = b.block_id)
             ORDER BY c.chain_name
        """)
        for row in rows:
            name = row[0]
            chain = abe._row_to_chain((row[8], name, row[9], row[10], row[11]))
            body += [
                '<tr><td><a href="chain/', escape(name), '">',
                escape(name), '</a></td><td>', escape(chain['code3']), '</td>']

            if row[1] is not None:
                (height, nTime, seconds, satoshis, ss, hash, total_ss) = (
                    int(row[1]), int(row[2]), int(row[3]), int(row[4]),
                    int(row[5]), abe.store.hashout_hex(row[6]), int(row[7]))

                started = nTime - seconds
                chain_age = now - started
                since_block = now - nTime

                if satoshis == 0:
                    avg_age = '&nbsp;'
                else:
                    avg_age = '%5g' % ((float(ss) / satoshis + since_block)
                                       / 86400.0)

                if chain_age <= 0:
                    percent_destroyed = '&nbsp;'
                else:
                    more = since_block * satoshis
                    percent_destroyed = '%5g' % (
                        100.0 - (100.0 * (ss + more) / (total_ss + more))) + '%'

                body += [
                    '<td><a href="block/', hash, '">', height, '</a></td>',
                    '<td>', format_time(nTime), '</td>',
                    '<td>', format_time(started)[:10], '</td>',
                    '<td>', '%5g' % (chain_age / 86400.0), '</td>',
                    '<td>', format_satoshis(satoshis, chain), '</td>',
                    '<td>', avg_age, '</td>',
                    '<td>', percent_destroyed, '</td>']
            body += ['</tr>\n']
        body += ['</table>\n']
        if len(rows) == 0:
            body += ['<p>No block data found.</p>\n']

    def _chain_fields(abe):
        return ["id", "name", "code3", "address_version", "last_block_id"]

    def _row_to_chain(abe, row):
        if row is None:
            raise NoSuchChainError()
        chain = {}
        fields = abe._chain_fields()
        for i in range(len(fields)):
            chain[fields[i]] = row[i]
        chain['address_version'] = abe.store.binout(chain['address_version'])
        return chain

    def chain_lookup_by_name(abe, symbol):
        if symbol is None:
            return abe.get_default_chain()
        return abe._row_to_chain(abe.store.selectrow("""
            SELECT chain_""" + ", chain_".join(abe._chain_fields()) + """
              FROM chain
             WHERE chain_name = ?""", (symbol,)))

    def get_default_chain(abe):
        return abe.chain_lookup_by_name('Bitcoin')

    def chain_lookup_by_id(abe, chain_id):
        return abe._row_to_chain(abe.store.selectrow("""
            SELECT chain_""" + ", chain_".join(abe._chain_fields()) + """
              FROM chain
             WHERE chain_id = ?""", (chain_id,)))

    def handle_chain(abe, page):
        symbol = wsgiref.util.shift_path_info(page['env'])
        chain = abe.chain_lookup_by_name(symbol)

        cmd = wsgiref.util.shift_path_info(page['env'])
        if cmd == 'b':
            return abe.show_block_number(chain, page)
        if cmd == '':
            #print "removing /"
            # Tolerate trailing slash.
            page['env']['SCRIPT_NAME'] = page['env']['SCRIPT_NAME'][:-1]
            raise Redirect()
        if cmd == 'q':
            return abe.handle_q(page, chain=chain)
        if cmd is not None:
            raise PageNotFound()

        page['title'] = chain['name']

        body = page['body']
        body += abe.search_form(page)

        count = get_int_param(page, 'count') or 20
        hi = get_int_param(page, 'hi')
        orig_hi = hi

        if hi is None:
            row = abe.store.selectrow("""
                SELECT b.block_height
                  FROM block b
                  JOIN chain c ON (c.chain_last_block_id = b.block_id)
                 WHERE c.chain_id = ?
            """, (chain['id'],))
            if row:
                hi = row[0]
        if hi is None:
            if orig_hi is None and count > 0:
                body += ['<p>I have no blocks in this chain.</p>']
            else:
                body += ['<p class="error">'
                         'The requested range contains no blocks.</p>\n']
            return True

        rows = abe.store.selectall("""
            SELECT b.block_hash, b.block_height, b.block_nTime, b.block_num_tx,
                   b.block_nBits, b.block_value_out,
                   b.block_total_seconds, b.block_satoshi_seconds,
                   b.block_total_satoshis, b.block_ss_destroyed,
                   b.block_total_ss
              FROM block b
              JOIN chain_candidate cc ON (b.block_id = cc.block_id)
             WHERE cc.chain_id = ?
               AND cc.block_height BETWEEN ? AND ?
               AND cc.in_longest = 1
             ORDER BY cc.block_height DESC LIMIT ?
        """, (chain['id'], hi - count + 1, hi, count))

        if hi is None:
            hi = int(rows[0][1])
        basename = os.path.basename(page['env']['PATH_INFO'])

        nav = ['<a href="',
               basename, '?count=', str(count), '">&lt;&lt;</a>']
        nav += [' <a href="', basename, '?hi=', str(hi + count),
                 '&amp;count=', str(count), '">&lt;</a>']
        nav += [' ', '&gt;']
        if hi >= count:
            nav[-1] = ['<a href="', basename, '?hi=', str(hi - count),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        nav += [' ', '&gt;&gt;']
        if hi != count - 1:
            nav[-1] = ['<a href="', basename, '?hi=', str(count - 1),
                        '&amp;count=', str(count), '">', nav[-1], '</a>']
        for c in (20, 50, 100, 500, 2016):
            nav += [' ']
            if c != count:
                nav += ['<a href="', basename, '?count=', str(c)]
                if hi is not None:
                    nav += ['&amp;hi=', str(max(hi, c - 1))]
                nav += ['">']
            nav += [' ', str(c)]
            if c != count:
                nav += ['</a>']

        nav += [' <a href="', page['dotdot'], '">Search</a>']

        extra = False
        #extra = True
        body += ['<p>', nav, '</p>\n',
                 '<table><tr><th>Block</th><th>Approx. Time</th>',
                 '<th>Transactions</th><th>Value Out</th>',
                 '<th>Difficulty</th><th>Outstanding</th>',
                 '<th>Average Age</th><th>Chain Age</th>',
                 '<th>% ',
                 '<a href="https://en.bitcoin.it/wiki/Bitcoin_Days_Destroyed">',
                 'CoinDD</a></th>',
                 ['<th>Satoshi-seconds</th>',
                  '<th>Total ss</th>']
                 if extra else '',
                 '</tr>\n']
        for row in rows:
            (hash, height, nTime, num_tx, nBits, value_out,
             seconds, ss, satoshis, destroyed, total_ss) = row
            nTime = int(nTime)
            value_out = int(value_out)
            seconds = int(seconds)
            satoshis = int(satoshis)
            ss = int(ss)
            total_ss = int(total_ss)

            if satoshis == 0:
                avg_age = '&nbsp;'
            else:
                avg_age = '%5g' % (ss / satoshis / 86400.0)

            if seconds <= 0:
                percent_destroyed = '&nbsp;'
            else:
                percent_destroyed = '%5g' % (
                    100.0 - (100.0 * ss / total_ss)) + '%'

            body += [
                '<tr><td><a href="', page['dotdot'], 'block/',
                abe.store.hashout_hex(hash),
                '">', height, '</a>'
                '</td><td>', format_time(int(nTime)),
                '</td><td>', num_tx,
                '</td><td>', format_satoshis(value_out, chain),
                '</td><td>', util.calculate_difficulty(int(nBits)),
                '</td><td>', format_satoshis(satoshis, chain),
                '</td><td>', avg_age,
                '</td><td>', '%5g' % (seconds / 86400.0),
                '</td><td>', percent_destroyed,
                ['</td><td>', '%8g' % ss,
                 '</td><td>', '%8g' % total_ss] if extra else '',
                '</td></tr>\n']

        body += ['</table>\n<p>', nav, '</p>\n']
        return True

    def _show_block(abe, where, bind, page, dotdotblock, chain):
        address_version = ('\0' if chain is None
                           else chain['address_version'])
        body = page['body']
        sql = """
            SELECT
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
             WHERE """ + where
        row = abe.store.selectrow(sql, bind)
        if (row is None):
            body += ['<p class="error">Block not found.</p>']
            return
        (block_id, block_hash, block_version, hashMerkleRoot,
         nTime, nBits, nNonce, height,
         prev_block_hash, block_chain_work, value_in, value_out,
         satoshis, seconds, ss, total_ss, destroyed, num_tx) = (
            row[0], abe.store.hashout_hex(row[1]), row[2],
            abe.store.hashout_hex(row[3]), row[4], int(row[5]), row[6],
            row[7], abe.store.hashout_hex(row[8]),
            abe.store.binout_int(row[9]), int(row[10]), int(row[11]),
            None if row[12] is None else int(row[12]),
            None if row[13] is None else int(row[13]),
            None if row[14] is None else int(row[14]),
            None if row[15] is None else int(row[15]),
            None if row[16] is None else int(row[16]),
            int(row[17]),
            )

        next_list = abe.store.selectall("""
            SELECT DISTINCT n.block_hash, cc.in_longest
              FROM block_next bn
              JOIN block n ON (bn.next_block_id = n.block_id)
              JOIN chain_candidate cc ON (n.block_id = cc.block_id)
             WHERE bn.block_id = ?
             ORDER BY cc.in_longest DESC""",
                                  (block_id,))

        if chain is None:
            page['title'] = ['Block ', block_hash[:4], '...', block_hash[-10:]]
        else:
            page['title'] = [escape(chain['name']), ' ', height]
            page['h1'] = ['<a href="', page['dotdot'], 'chain/',
                          escape(chain['name']), '?hi=', height, '">',
                          escape(chain['name']), '</a> ', height]

        body += short_link(page, 'b/' + block_shortlink(block_hash))

        body += ['<p>Hash: ', block_hash, '<br />\n']

        if prev_block_hash is not None:
            body += ['Previous Block: <a href="', dotdotblock,
                     prev_block_hash, '">', prev_block_hash, '</a><br />\n']
        if next_list:
            body += ['Next Block: ']
        for row in next_list:
            hash = abe.store.hashout_hex(row[0])
            body += ['<a href="', dotdotblock, hash, '">', hash, '</a><br />\n']

        body += [
            'Height: ', height, '<br />\n',
            'Version: ', block_version, '<br />\n',
            'Transaction Merkle Root: ', hashMerkleRoot, '<br />\n',
            'Time: ', nTime, ' (', format_time(nTime), ')<br />\n',
            'Difficulty: ', format_difficulty(util.calculate_difficulty(nBits)),
            ' (Bits: %x)' % (nBits,), '<br />\n',
            'Cumulative Difficulty: ', format_difficulty(
                util.work_to_difficulty(block_chain_work)), '<br />\n',
            'Nonce: ', nNonce, '<br />\n',
            'Transactions: ', num_tx, '<br />\n',
            'Value out: ', format_satoshis(value_out, chain), '<br />\n',

            ['Average Coin Age: %6g' % (ss / 86400.0 / satoshis,),
             ' days<br />\n']
            if satoshis and (ss is not None) else '',

            '' if destroyed is None else
            ['Coin-days Destroyed: ',
             format_satoshis(destroyed / 86400.0, chain), '<br />\n'],

            ['Cumulative Coin-days Destroyed: %6g%%<br />\n' %
             (100 * (1 - float(ss) / total_ss),)]
            if total_ss else '',

            ['sat=',satoshis,';sec=',seconds,';ss=',ss,
             ';total_ss=',total_ss,';destroyed=',destroyed]
            if abe.debug else '',

            '</p>\n']

        body += ['<h3>Transactions</h3>\n']

        tx_ids = []
        txs = {}
        block_out = 0
        block_in = 0
        for row in abe.store.selectall("""
            SELECT tx_id, tx_hash, tx_size, txout_value, pubkey_hash
              FROM txout_detail
             WHERE block_id = ?
             ORDER BY tx_pos, txout_pos
        """, (block_id,)):
            tx_id, tx_hash_hex, tx_size, txout_value, pubkey_hash = (
                row[0], abe.store.hashout_hex(row[1]), int(row[2]),
                int(row[3]), abe.store.binout(row[4]))
            tx = txs.get(tx_id)
            if tx is None:
                tx_ids.append(tx_id)
                txs[tx_id] = {
                    "hash": tx_hash_hex,
                    "total_out": 0,
                    "total_in": 0,
                    "out": [],
                    "in": [],
                    "size": tx_size,
                    }
                tx = txs[tx_id]
            tx['total_out'] += txout_value
            block_out += txout_value
            tx['out'].append({
                    "value": txout_value,
                    "pubkey_hash": pubkey_hash,
                    })
        for row in abe.store.selectall("""
            SELECT tx_id, txin_value, pubkey_hash
              FROM txin_detail
             WHERE block_id = ?
             ORDER BY tx_pos, txin_pos
        """, (block_id,)):
            tx_id, txin_value, pubkey_hash = (
                row[0], 0 if row[1] is None else int(row[1]),
                abe.store.binout(row[2]))
            tx = txs.get(tx_id)
            if tx is None:
                # Strange, inputs but no outputs?
                tx_ids.append(tx_id)
                #row2 = abe.store.selectrow("""
                #    SELECT tx_hash, tx_size FROM tx WHERE tx_id = ?""",
                #                           (tx_id,))
                txs[tx_id] = {
                    "hash": "AssertionFailedTxInputNoOutput",
                    "total_out": 0,
                    "total_in": 0,
                    "out": [],
                    "in": [],
                    "size": -1,
                    }
                tx = txs[tx_id]
            tx['total_in'] += txin_value
            block_in += txin_value
            tx['in'].append({
                    "value": txin_value,
                    "pubkey_hash": pubkey_hash,
                    })

        body += ['<table><tr><th>Transaction</th><th>Fee</th>'
                 '<th>Size (kB)</th><th>From (amount)</th><th>To (amount)</th>'
                 '</tr>\n']
        for tx_id in tx_ids:
            tx = txs[tx_id]
            is_coinbase = (tx_id == tx_ids[0])
            if is_coinbase:
                fees = 0
            else:
                fees = tx['total_in'] - tx['total_out']
            body += ['<tr><td><a href="../tx/' + tx['hash'] + '">',
                     tx['hash'][:10], '...</a>'
                     '</td><td>', format_satoshis(fees, chain),
                     '</td><td>', tx['size'] / 1000.0,
                     '</td><td>']
            if is_coinbase:
                gen = block_out - block_in
                fees = tx['total_out'] - gen
                body += ['Generation: ', format_satoshis(gen, chain),
                         ' + ', format_satoshis(fees, chain), ' total fees']
            else:
                for txin in tx['in']:
                    body += hash_to_address_link(
                        address_version, txin['pubkey_hash'], page['dotdot'])
                    body += [': ', format_satoshis(txin['value'], chain),
                             '<br />']
            body += ['</td><td>']
            for txout in tx['out']:
                body += hash_to_address_link(
                    address_version, txout['pubkey_hash'], page['dotdot'])
                body += [': ', format_satoshis(txout['value'], chain), '<br />']
            body += ['</td></tr>\n']
        body += '</table>\n'

    def show_block_number(abe, chain, page):
        height = wsgiref.util.shift_path_info(page['env'])
        try:
            height = int(height)
        except:
            raise PageNotFound()
        if height < 0 or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = [escape(chain['name']), ' ', height]
        abe._show_block('chain_id = ? AND block_height = ? AND in_longest = 1',
                        (chain['id'], height), page, page['dotdot'] + 'block/',
                        chain)

    def handle_block(abe, page):
        block_hash = wsgiref.util.shift_path_info(page['env'])
        if block_hash in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = 'Block'

        if not HASH_PREFIX_RE.match(block_hash):
            page['body'] += ['<p class="error">Not a valid block hash.</p>']
            return

        # Try to show it as a block number, not a block hash.

        dbhash = abe.store.hashin_hex(block_hash)

        # XXX arbitrary choice: minimum chain_id.  Should support
        # /chain/CHAIN/block/HASH URLs and try to keep "next block"
        # links on the chain.
        row = abe.store.selectrow("""
            SELECT MIN(cc.chain_id), cc.block_id, cc.block_height
              FROM chain_candidate cc
              JOIN block b ON (cc.block_id = b.block_id)
             WHERE b.block_hash = ? AND cc.in_longest = 1
             GROUP BY cc.block_id, cc.block_height""",
            (dbhash,))
        if row is None:
            abe._show_block('block_hash = ?', (dbhash,), page, '', None)
        else:
            chain_id, block_id, height = row
            chain = abe.chain_lookup_by_id(chain_id)
            page['title'] = [escape(chain['name']), ' ', height]
            abe._show_block('block_id = ?', (block_id,), page, '', chain)

    def handle_tx(abe, page):
        tx_hash = wsgiref.util.shift_path_info(page['env'])
        if tx_hash in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = ['Transaction ', tx_hash[:10], '...', tx_hash[-4:]]
        body = page['body']

        if not HASH_PREFIX_RE.match(tx_hash):
            body += ['<p class="error">Not a valid transaction hash.</p>']
            return

        row = abe.store.selectrow("""
            SELECT tx_id, tx_version, tx_lockTime, tx_size
              FROM tx
             WHERE tx_hash = ?
        """, (abe.store.hashin_hex(tx_hash),))
        if row is None:
            body += ['<p class="error">Transaction not found.</p>']
            return
        tx_id, tx_version, tx_lockTime, tx_size = (
            int(row[0]), int(row[1]), int(row[2]), int(row[3]))

        block_rows = abe.store.selectall("""
            SELECT c.chain_name, cc.in_longest,
                   b.block_nTime, b.block_height, b.block_hash,
                   block_tx.tx_pos
              FROM chain c
              JOIN chain_candidate cc ON (cc.chain_id = c.chain_id)
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
             WHERE block_tx.tx_id = ?
             ORDER BY c.chain_id, cc.in_longest DESC, b.block_hash
        """, (tx_id,))

        def parse_row(row):
            pos, script, value, o_hash, o_pos, binaddr = row
            return {
                "pos": int(pos),
                "script": abe.store.binout(script),
                "value": None if value is None else int(value),
                "o_hash": abe.store.hashout_hex(o_hash),
                "o_pos": None if o_pos is None else int(o_pos),
                "binaddr": abe.store.binout(binaddr),
                }

        def row_to_html(row, this_ch, other_ch, no_link_text):
            body = page['body']
            body += [
                '<tr>\n',
                '<td><a name="', this_ch, row['pos'], '">', row['pos'],
                '</a></td>\n<td>']
            if row['o_hash'] is None:
                body += [no_link_text]
            else:
                body += [
                    '<a href="', row['o_hash'], '#', other_ch, row['o_pos'],
                    '">', row['o_hash'][:10], '...:', row['o_pos'], '</a>']
            body += [
                '</td>\n',
                '<td>', format_satoshis(row['value'], chain), '</td>\n',
                '<td>']
            if row['binaddr'] is None:
                body += ['Unknown']
            else:
                body += hash_to_address_link(chain['address_version'],
                                             row['binaddr'], '../')
            body += [
                '</td>\n',
                '<td>', escape(decode_script(row['script'])),
                '</td>\n</tr>\n']

        # XXX Unneeded outer join.
        in_rows = map(parse_row, abe.store.selectall("""
            SELECT
                txin.txin_pos,
                txin.txin_scriptSig,
                txout.txout_value,
                COALESCE(prevtx.tx_hash, u.txout_tx_hash),
                COALESCE(txout.txout_pos, u.txout_pos),
                pubkey.pubkey_hash
              FROM txin
              LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx prevtx ON (txout.tx_id = prevtx.tx_id)
              LEFT JOIN unlinked_txin u ON (u.txin_id = txin.txin_id)
             WHERE txin.tx_id = ?
             ORDER BY txin.txin_pos
        """, (tx_id,)))

        # XXX Only two outer JOINs needed.
        out_rows = map(parse_row, abe.store.selectall("""
            SELECT
                txout.txout_pos,
                txout.txout_scriptPubKey,
                txout.txout_value,
                nexttx.tx_hash,
                txin.txin_pos,
                pubkey.pubkey_hash
              FROM txout
              LEFT JOIN txin ON (txin.txout_id = txout.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx nexttx ON (txin.tx_id = nexttx.tx_id)
             WHERE txout.tx_id = ?
             ORDER BY txout.txout_pos
        """, (tx_id,)))

        def sum_values(rows):
            ret = 0
            for row in rows:
                if row['value'] is None:
                    return None
                ret += row['value']
            return ret

        value_in = sum_values(in_rows)
        value_out = sum_values(out_rows)
        is_coinbase = None

        body += short_link(page, 't/' + hexb58(tx_hash[:14]))
        body += ['<p>Hash: ', tx_hash, '<br />\n']
        chain = None
        for row in block_rows:
            (name, in_longest, nTime, height, blk_hash, tx_pos) = (
                row[0], int(row[1]), int(row[2]), int(row[3]),
                abe.store.hashout_hex(row[4]), int(row[5]))
            if chain is None:
                chain = abe.chain_lookup_by_name(name)
                is_coinbase = (tx_pos == 0)
            elif name <> chain['name']:
                abe.log.warn('Transaction ' + tx_hash + ' in multiple chains: '
                             + name + ', ' + chain['name'])
            body += [
                'Appeared in <a href="../block/', blk_hash, '">',
                escape(name), ' ',
                height if in_longest else [blk_hash[:10], '...', blk_hash[-4:]],
                '</a> (', format_time(nTime), ')<br />\n']

        if chain is None:
            abe.log.warn('Assuming default chain for Transaction ' + tx_hash)
            chain = abe.get_default_chain()

        body += [
            'Number of inputs: ', len(in_rows),
            ' (<a href="#inputs">Jump to inputs</a>)<br />\n',
            'Total in: ', format_satoshis(value_in, chain), '<br />\n',
            'Number of outputs: ', len(out_rows),
            ' (<a href="#outputs">Jump to outputs</a>)<br />\n',
            'Total out: ', format_satoshis(value_out, chain), '<br />\n',
            'Size: ', tx_size, ' bytes<br />\n',
            'Fee: ', format_satoshis(0 if is_coinbase else
                                     (value_in and value_out and
                                      value_in - value_out), chain),
            '<br />\n']
        body += ['</p>\n',
                 '<a name="inputs"><h3>Inputs</h3></a>\n<table>\n',
                 '<tr><th>Index</th><th>Previous output</th><th>Amount</th>',
                 '<th>From address</th><th>ScriptSig</th></tr>\n']
        for row in in_rows:
            row_to_html(row, 'i', 'o',
                        'Generation' if is_coinbase else 'Unknown')
        body += ['</table>\n',
                 '<a name="outputs"><h3>Outputs</h3></a>\n<table>\n',
                 '<tr><th>Index</th><th>Redeemed at input</th><th>Amount</th>',
                 '<th>To address</th><th>ScriptPubKey</th></tr>\n']
        for row in out_rows:
            row_to_html(row, 'o', 'i', 'Not yet redeemed')

        body += ['</table>\n']

    def handle_address(abe, page):
        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        body = page['body']
        page['title'] = 'Address ' + escape(address)
        version, binaddr = decode_check_address(address)
        if binaddr is None:
            body += ['<p>Not a valid address.</p>']
            return

        dbhash = abe.store.binin(binaddr)

        chains = {}
        balance = {}
        received = {}
        sent = {}
        count = [0, 0]
        chain_ids = []
        def adj_balance(txpoint):
            chain_id = txpoint['chain_id']
            value = txpoint['value']
            if chain_id not in balance:
                chain_ids.append(chain_id)
                chains[chain_id] = abe.chain_lookup_by_id(chain_id)
                balance[chain_id] = 0
                received[chain_id] = 0
                sent[chain_id] = 0
            balance[chain_id] += value
            if value > 0:
                received[chain_id] += value
            else:
                sent[chain_id] -= value
            count[txpoint['is_in']] += 1

        txpoints = []
        rows = []
        rows += abe.store.selectall("""
            SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                1,
                b.block_hash,
                tx.tx_hash,
                txin.txin_pos,
                -prevout.txout_value
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txin ON (txin.tx_id = tx.tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey ON (pubkey.pubkey_id = prevout.pubkey_id)
             WHERE pubkey.pubkey_hash = ?
               AND cc.in_longest = 1""",
                      (dbhash,))
        rows += abe.store.selectall("""
            SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                0,
                b.block_hash,
                tx.tx_hash,
                txout.txout_pos,
                txout.txout_value
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txout ON (txout.tx_id = tx.tx_id)
              JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
             WHERE pubkey.pubkey_hash = ?
               AND cc.in_longest = 1""",
                      (dbhash,))
        rows.sort()
        for row in rows:
            nTime, chain_id, height, is_in, blk_hash, tx_hash, pos, value = row
            txpoint = {
                    "nTime":    int(nTime),
                    "chain_id": int(chain_id),
                    "height":   int(height),
                    "is_in":    int(is_in),
                    "blk_hash": abe.store.hashout_hex(blk_hash),
                    "tx_hash":  abe.store.hashout_hex(tx_hash),
                    "pos":      int(pos),
                    "value":    int(value),
                    }
            adj_balance(txpoint)
            txpoints.append(txpoint)

        if (not chain_ids):
            body += ['<p>Address not seen on the network.</p>']
            return

        def format_amounts(amounts, link):
            ret = []
            for chain_id in chain_ids:
                chain = chains[chain_id]
                if chain_id != chain_ids[0]:
                    ret += [', ']
                ret += [format_satoshis(amounts[chain_id], chain),
                        ' ', escape(chain['code3'])]
                if link:
                    other = hash_to_address(chain['address_version'], binaddr)
                    if other != address:
                        ret[-1] = ['<a href="', page['dotdot'],
                                   'address/', other,
                                   '">', ret[-1], '</a>']
            return ret

        body += short_link(page, 'a/' + address[:10])

        body += ['<p>Balance: '] + format_amounts(balance, True)

        for chain_id in chain_ids:
            balance[chain_id] = 0  # Reset for history traversal.

        body += ['<br />\n',
                 'Transactions in: ', count[0], '<br />\n',
                 'Received: ', format_amounts(received, False), '<br />\n',
                 'Transactions out: ', count[1], '<br />\n',
                 'Sent: ', format_amounts(sent, False), '<br />\n']

        body += ['</p>\n'
                 '<h3>Transactions</h3>\n'
                 '<table>\n<tr><th>Transaction</th><th>Block</th>'
                 '<th>Approx. Time</th><th>Amount</th><th>Balance</th>'
                 '<th>Currency</th></tr>\n']

        for elt in txpoints:
            chain = chains[elt['chain_id']]
            balance[elt['chain_id']] += elt['value']
            body += ['<tr><td><a href="../tx/', elt['tx_hash'],
                     '#', 'i' if elt['is_in'] else 'o', elt['pos'],
                     '">', elt['tx_hash'][:10], '...</a>',
                     '</td><td><a href="../block/', elt['blk_hash'],
                     '">', elt['height'], '</a></td><td>',
                     format_time(elt['nTime']), '</td><td>']
            if elt['value'] < 0:
                body += ['(', format_satoshis(-elt['value'], chain), ')']
            else:
                body += [format_satoshis(elt['value'], chain)]
            body += ['</td><td>',
                     format_satoshis(balance[elt['chain_id']], chain),
                     '</td><td>', escape(chain['code3']),
                     '</td></tr>\n']
        body += ['</table>\n']

    def search_form(abe, page):
        q = (page['params'].get('q') or [''])[0]
        return [
            '<p>Search by address, block number, block or transaction hash,'
            ' or chain name:</p>\n'
            '<form action="', page['dotdot'], 'search"><p>\n'
            '<input name="q" size="64" value="', escape(q), '" />'
            '<button type="submit">Search</button>\n'
            '<br />Address or hash search requires at least the first six'
            ' characters.</p></form>\n']

    def handle_search(abe, page):
        page['title'] = 'Search'
        q = (page['params'].get('q') or [''])[0]
        if q == '':
            page['body'] = [
                '<p>Please enter search terms.</p>\n', abe.search_form(page)]
            return

        found = []
        if HEIGHT_RE.match(q):      found += abe.search_number(int(q))
        if ADDRESS_RE.match(q):     found += abe.search_address(q)
        elif ADDR_PREFIX_RE.match(q):found += abe.search_address_prefix(q)
        if HASH_PREFIX_RE.match(q): found += abe.search_hash_prefix(q)
        found += abe.search_general(q)
        abe.show_search_results(page, found)

    def show_search_results(abe, page, found):
        if not found:
            page['body'] = [
                '<p>No results found.</p>\n', abe.search_form(page)]
            return

        if len(found) == 1:
            # Undo shift_path_info.
            sn = posixpath.dirname(page['env']['SCRIPT_NAME'])
            if sn == '/': sn = ''
            page['env']['SCRIPT_NAME'] = sn
            page['env']['PATH_INFO'] = '/' + page['dotdot'] + found[0]['uri']
            del(page['env']['QUERY_STRING'])
            raise Redirect()

        body = page['body']
        body += ['<h3>Search Results</h3>\n<ul>\n']
        for result in found:
            body += [
                '<li><a href="', page['dotdot'], escape(result['uri']), '">',
                escape(result['name']), '</a></li>\n']
        body += ['</ul>\n']

    def search_number(abe, n):
        def process(row):
            (chain_name, dbhash, in_longest) = row
            hexhash = abe.store.hashout_hex(dbhash)
            if in_longest == 1:
                name = str(n)
            else:
                name = hexhash
            return {
                'name': chain_name + ' ' + name,
                'uri': 'block/' + hexhash,
                }

        return map(process, abe.store.selectall("""
            SELECT c.chain_name, b.block_hash, cc.in_longest
              FROM chain c
              JOIN chain_candidate cc ON (cc.chain_id = c.chain_id)
              JOIN block b ON (b.block_id = cc.block_id)
             WHERE cc.block_height = ?
             ORDER BY c.chain_name, cc.in_longest DESC
        """, (n,)))

    def search_hash_prefix(abe, q, types = ('tx', 'block')):
        lo = abe.store.hashin_hex(q + '0' * (64 - len(q)))
        hi = abe.store.hashin_hex(q + 'f' * (64 - len(q)))
        ret = []
        for t in types:
            def process(row):
                hash = abe.store.hashout_hex(row[0])
                name = 'Transaction' if t == 'tx' else 'Block'
                return {
                    'name': name + ' ' + hash,
                    'uri': t + '/' + hash,
                    }
            ret += map(process, abe.store.selectall(
                "SELECT " + t + "_hash FROM " + t + " WHERE " + t +
                # XXX hardcoded limit.
                "_hash BETWEEN ? AND ? LIMIT 100",
                (lo, hi)))
        return ret

    def search_address(abe, address):
        try:
            binaddr = base58.bc_address_to_hash_160(address)
        except:
            return abe.search_address_prefix(address)
        return [{ 'name': 'Address ' + address, 'uri': 'address/' + address }]

    def search_address_prefix(abe, ap):
        ret = []
        ones = 0
        for c in ap:
            if c != '1':
                break
            ones += 1
        all_ones = (ones == len(ap))
        minlen = max(len(ap), 24)
        l = max(35, len(ap))  # XXX Increase "35" to support multibyte
                              # address versions.
        al = ap + ('1' * (l - len(ap)))
        ah = ap + ('z' * (l - len(ap)))

        def incr_str(s):
            for i in range(len(s)-1, -1, -1):
                if s[i] != '\xff':
                    return s[:i] + chr(ord(s[i])+1) + ('\0' * (len(s) - i - 1))
            return '\1' + ('\0' * len(s))

        def process(row):
            hash = abe.store.binout(row[0])
            address = hash_to_address(vl, hash)
            if address.startswith(ap):
                v = vl
            else:
                if vh != vl:
                    address = hash_to_address(vh, hash)
                    if not address.startswith(ap):
                        return None
                    v = vh
            if abe.is_address_version(v):
                return {
                    'name': 'Address ' + address,
                    'uri': 'address/' + address,
                    }

        while l >= minlen:
            vl, hl = decode_address(al)
            vh, hh = decode_address(ah)
            if ones:
                if not all_ones and hash_to_address('\0', hh)[ones:][:1] == '1':
                    break
            elif vh == '\0':
                break
            elif vh != vl and vh != incr_str(vl):
                continue
            if hl <= hh:
                neg = ""
            else:
                neg = " NOT"
                hl, hh = hh, hl
            bl = abe.store.binin(hl)
            bh = abe.store.binin(hh)
            ret += filter(None, map(process, abe.store.selectall(
                "SELECT pubkey_hash FROM pubkey WHERE pubkey_hash" +
                # XXX hardcoded limit.
                neg + " BETWEEN ? AND ? LIMIT 100", (bl, bh))))
            l -= 1
            al = al[:-1]
            ah = ah[:-1]

        return ret

    def search_general(abe, q):
        """Search for something that is not an address, hash, or block number.
        Currently, this is limited to chain names and currency codes."""
        def process(row):
            (name, code3) = row
            return { 'name': name + ' (' + code3 + ')',
                     'uri': 'chain/' + str(name) }
        ret = map(process, abe.store.selectall("""
            SELECT chain_name, chain_code3
              FROM chain
             WHERE UPPER(chain_name) LIKE '%' || ? || '%'
                OR UPPER(chain_code3) LIKE '%' || ? || '%'
        """, (q.upper(), q.upper())))
        return ret

    def handle_t(abe, page):
        abe.show_search_results(
            page,
            abe.search_hash_prefix(
                b58hex(wsgiref.util.shift_path_info(page['env'])),
                ('tx',)))

    def handle_b(abe, page):
        abe.show_search_results(
            page,
            abe.search_hash_prefix(
                shortlink_block(wsgiref.util.shift_path_info(page['env'])),
                ('block',)))

    def handle_a(abe, page):
        abe.show_search_results(
            page,
            abe.search_address_prefix(
                wsgiref.util.shift_path_info(page['env'])))

    def handle_q(abe, page, chain=None):
        cmd = wsgiref.util.shift_path_info(page['env'])
        if cmd is None:
            return abe.q(page)

        func = getattr(abe, 'q_' + cmd, None)
        if func is None:
            raise PageNotFound()

        page['content_type'] = 'text/plain'
        page['template'] = '%(body)s'
        page['body'] = func(page, chain)

    def q(abe, page):
        page['body'] = ['<p>Supported APIs:</p>\n<ul>\n']
        for name in dir(abe):
            if not name.startswith("q_"):
                continue
            cmd = name[2:]
            page['body'] += ['<li><a href="q/', cmd, '">', cmd, '</a>']
            val = getattr(abe, name)
            if val.__doc__ is not None:
                page['body'] += [' - ', escape(val.__doc__)]
            page['body'] += ['</li>\n']
        page['body'] += ['</ul>\n']

    def q_getblockcount(abe, page, chain):
        """shows the current block number."""
        if chain is None:
            return 'Shows the greatest block height in CHAIN.\n' \
                '/chain/CHAIN/q/getblockcount\n'
        # "getblockcount" traditionally returns max(block_height),
        # which is one less than the actual block count.
        (height,) = abe.store.selectrow("""
            SELECT MAX(block_height)
              FROM chain_candidate
             WHERE chain_id = ?
               AND in_longest = 1""", (chain['id'],))
        return -1 if height is None else height

    def q_translate_address(abe, page, chain):
        """shows the address in a given chain with a given address's hash."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'Translates ADDRESS for use in CHAIN.\n' \
                '/chain/CHAIN/q/translate_address/ADDRESS\n'
        version, hash = decode_check_address(addr)
        if hash is None:
            return addr + " (INVALID ADDRESS)"
        return hash_to_address(chain['address_version'], hash)

    def q_decode_address(abe, page, chain):
        """shows the version prefix and hash encoded in an address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return "Shows ADDRESS's version byte(s) and public key hash" \
                ' as hex strings separated by colon (":").\n' \
                '/q/decode_address/ADDRESS\n'
        version, hash = decode_address(addr)
        ret = binascii.hexlify(version) + ":" + binascii.hexlify(hash)
        if hash_to_address(version, hash) != addr:
            ret = "INVALID(" + ret + ")"
        return ret

    def q_addresstohash(abe, page, chain):
        """shows the public key hash encoded in an address."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return 'Shows the 160-bit hash encoded in ADDRESS.\n' \
                'For BBE compatibility, the address is not checked for' \
                ' validity.  See also /q/decode_address.\n' \
                '/q/addresstohash/ADDRESS\n'
        version, hash = decode_address(addr)
        return binascii.hexlify(hash).upper()

    def q_hashtoaddress(abe, page, chain):
        """shows the address with the given version prefix and hash."""
        arg1 = wsgiref.util.shift_path_info(page['env'])
        arg2 = wsgiref.util.shift_path_info(page['env'])
        if arg1 is None:
            return \
                'Converts a 160-bit hash and address version to an address.\n' \
                '/q/hashtoaddress/HASH[/VERSION]\n'

        if page['env']['PATH_INFO']:
            return "ERROR: Too many arguments"

        if arg2 is not None:
            # BBE-compatible HASH/VERSION
            version, hash = arg2, arg1

        elif arg1.find(":") >= 0:
            # VERSION:HASH as returned by /q/decode_address.
            version, hash = arg1.split(":", 1)

        elif chain:
            version, hash = binascii.hexlify(chain['address_version']), arg1

        else:
            # Default: Bitcoin address starting with "1".
            version, hash = '00', arg1

        try:
            hash = binascii.unhexlify(hash)
            version = binascii.unhexlify(version)
        except:
            return 'ERROR: Arguments must be hexadecimal strings of even length'
        return hash_to_address(version, hash)

    def q_hashpubkey(abe, page, chain):
        """shows the 160-bit hash of the given public key."""
        pubkey = wsgiref.util.shift_path_info(page['env'])
        if pubkey is None:
            return \
                "Returns the 160-bit hash of PUBKEY.\n" \
                "For example, the Bitcoin genesis block's output public key," \
                " seen in its transaction output scriptPubKey, starts with\n" \
                "04678afdb0fe..., and its hash is" \
                " 62E907B15CBF27D5425399EBF6F0FB50EBB88F18, corresponding" \
                " to address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.\n" \
                "/q/hashpubkey/PUBKEY\n"
        try:
            pubkey = binascii.unhexlify(pubkey)
        except:
            return 'ERROR: invalid hexadecimal byte string.'
        return binascii.hexlify(util.pubkey_to_hash(pubkey)).upper()

    def q_checkaddress(abe, page, chain):
        """checks an address for validity."""
        addr = wsgiref.util.shift_path_info(page['env'])
        if addr is None:
            return \
                "Returns the version encoded in ADDRESS as a hex string.\n" \
                "If ADDRESS is invalid, returns either X5, SZ, or CK for" \
                " BBE compatibility.\n" \
                "/q/checkaddress/ADDRESS\n"
        if ADDRESS_RE.match(addr):
            version, hash = decode_address(addr)
            if hash_to_address(version, hash) == addr:
                return binascii.hexlify(version).upper()
            return 'CK'
        if len(addr) >= 26:
            return 'X5'
        return 'SZ'

    def q_nethash(abe, page, chain):
        """shows statistics about difficulty and network power."""
        if chain is None:
            return 'Shows statistics every INTERVAL blocks.\n' \
                '/chain/CHAIN/q/nethash[/INTERVAL[/START[/STOP]]]\n'
        interval = path_info_uint(page, 144) or 144
        start = path_info_uint(page, 0)
        stop = path_info_uint(page, None)

        # Select every INTERVAL blocks from START to STOP.
        # Standard SQL lacks an "every Nth row" feature, so we
        # provide it with the help of a table containing the integers.
        # We don't need all integers, only as many as rows we want to
        # fetch.  We happen to have a table with the desired integers,
        # namely chain_candidate; its block_height column covers the
        # required range without duplicates if properly constrained.
        # That is the story of the second JOIN.

        if stop is not None:
            stop_ix = (stop - start) / interval

        rows = abe.store.selectall("""
            SELECT b.block_height,
                   b.block_nTime,
                   b.block_chain_work,
                   b.block_nBits
              FROM block b
              JOIN chain_candidate cc ON (cc.block_id = b.block_id)
              JOIN chain_candidate ints ON (
                       ints.chain_id = cc.chain_id
                   AND ints.in_longest = 1
                   AND ints.block_height * ? + ? = cc.block_height)
             WHERE cc.in_longest = 1
               AND cc.chain_id = ?""" + (
                "" if stop is None else """
               AND ints.block_height <= ?""") + """
             ORDER BY cc.block_height""",
                                   (interval, start, chain['id'])
                                   if stop is None else
                                   (interval, start, chain['id'], stop_ix))
        ret = NETHASH_HEADER

        for row in rows:
            height, nTime, chain_work, nBits = row
            nTime            = float(nTime)
            nBits            = int(nBits)
            target           = util.calculate_target(nBits)
            difficulty       = util.target_to_difficulty(target)
            work             = util.target_to_work(target)
            chain_work       = abe.store.binout_int(chain_work) - work

            if row is not rows[0]:
                height           = int(height)
                interval_work    = chain_work - prev_chain_work
                avg_target       = util.work_to_target(interval_work / interval)
                #if avg_target == target - 1:
                #    avg_target = target
                interval_seconds = nTime - prev_nTime
                if interval_seconds <= 0:
                    nethash = 'Infinity'
                else:
                    nethash = "%.0f" % (interval_work / interval_seconds,)
                ret += "%d,%d,%d,%d,%.3f,%d,%.0f,%s\n" % (
                    height, nTime, target, avg_target, difficulty, work,
                    interval_seconds / interval, nethash)

            prev_nTime, prev_chain_work = nTime, chain_work

        return ret

    def q_totalbc(abe, page, chain):
        """shows the amount of currency ever mined."""
        if chain is None:
            return 'Shows the amount of currency ever mined.\n' \
                'This differs from the amount in circulation when' \
                ' coins are destroyed, as happens frequently in Namecoin.\n' \
                'Unlike http://blockexplorer.com/q/totalbc, this does not' \
                ' support future block numbers, and it returns a sum of' \
                ' observed generations rather than a calculated value.\n' \
                '/chain/CHAIN/q/totalbc[/HEIGHT]\n'
        height = path_info_uint(page, None)
        if height is None:
            row = abe.store.selectrow("""
                SELECT b.block_total_satoshis
                  FROM chain c
                  LEFT JOIN block b ON (c.chain_last_block_id = b.block_id)
                 WHERE c.chain_id = ?
            """, (chain['id'],))
        else:
            row = abe.store.selectrow("""
                SELECT b.block_total_satoshis
                  FROM chain_candidate cc
                  LEFT JOIN block b ON (b.block_id = cc.block_id)
                 WHERE cc.chain_id = ?
                   AND cc.block_height = ?
                   AND cc.in_longest = 1
            """, (chain['id'], height))
            if not row:
                return 'ERROR: block %d not seen yet' % (height,)
        return format_satoshis(row[0], chain) if row else 0

    def q_getreceivedbyaddress(abe, page, chain):
        """getreceivedbyaddress"""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'returns amount of money received by given address (not balance, sends are not subtracted)\n' \
                '/chain/CHAIN/q/getreceivedbyaddress/ADDRESS\n'

        if ADDRESS_RE.match(addr):
            version, hash = decode_address(addr)
            sql = """
                SELECT COALESCE(SUM(txout.txout_value), 0)
                  FROM pubkey
                  JOIN txout ON txout.pubkey_id=pubkey.pubkey_id
                  JOIN block_tx ON block_tx.tx_id=txout.tx_id
                  JOIN block b ON b.block_id=block_tx.block_id
                  JOIN chain_candidate cc ON cc.block_id=b.block_id
                  WHERE
                      pubkey.pubkey_hash = ? AND
                      cc.chain_id = ? AND
                      cc.in_longest = 1"""
            row = abe.store.selectrow(
                sql, (abe.store.binin(hash), chain['id']))
            ret = format_satoshis(row[0], chain);
        else:
            ret = 'ERROR: address invalid'

        return ret

    def q_getsentbyaddress(abe, page, chain):
        """getsentbyaddress"""
        addr = wsgiref.util.shift_path_info(page['env'])
        if chain is None or addr is None:
            return 'returns amount of money sent from given address\n' \
                '/chain/CHAIN/q/getsentbyaddress/ADDRESS\n'

        if ADDRESS_RE.match(addr):
            version, hash = decode_address(addr)
            sql = """
                SELECT COALESCE(SUM(txout.txout_value), 0)
                  FROM pubkey
                  JOIN txout txout on txout.pubkey_id=pubkey.pubkey_id
                  JOIN txin on txin.txout_id=txout.txout_id
                  JOIN block_tx on block_tx.tx_id=txout.tx_id
                  JOIN block b on b.block_id=block_tx.block_id
                  JOIN chain_candidate cc on cc.block_id=b.block_id
                  WHERE
                      pubkey.pubkey_hash = ? AND
                      cc.chain_id = ? AND
                      cc.in_longest = 1"""
            row = abe.store.selectrow(
                sql, (abe.store.binin(hash), chain['id']))
            ret = format_satoshis(row[0], chain);
        else:
            ret = 'ERROR: address invalid'

        return ret

    def handle_download(abe, page):
        name = abe.args.download_name
        if name is None:
            name = re.sub(r'\W+', '-', ABE_APPNAME.lower()) + '-' + ABE_VERSION
        fileobj = lambda: None
        fileobj.func_dict['write'] = page['start_response'](
            '200 OK',
            [('Content-type', 'application/x-gtar-compressed'),
             ('Content-disposition', 'filename=' + name + '.tar.gz')])
        import tarfile
        with tarfile.TarFile.open(fileobj=fileobj, mode='w|gz',
                                  format=tarfile.PAX_FORMAT) as tar:
            tar.add(os.path.split(__file__)[0], name)
        raise Streamed()

    def serve_static(abe, path, start_response):
        slen = len(abe.static_path)
        if path[:slen] != abe.static_path:
            raise PageNotFound()
        path = path[slen:]
        try:
            # Serve static content.
            # XXX Should check file modification time and handle HTTP
            # if-modified-since.  Or just hope serious users will map
            # our htdocs as static in their web server.
            # XXX is "+ '/' + path" adequate for non-POSIX systems?
            found = open(abe.htdocs + '/' + path, "rb")
            import mimetypes
            (type, enc) = mimetypes.guess_type(path)
            # XXX Should do something with enc if not None.
            # XXX Should set Content-length.
            start_response('200 OK', [('Content-type', type or 'text/plain')])
            return found
        except IOError:
            raise PageNotFound()

    # Change this if you want multi-byte address versions.
    def is_address_version(abe, v):
        return len(v) == 1

def find_htdocs():
    return os.path.join(os.path.split(__file__)[0], 'htdocs')

def get_int_param(page, name):
    vals = page['params'].get(name)
    return vals and int(vals[0])

def path_info_uint(page, default):
    s = wsgiref.util.shift_path_info(page['env'])
    if s is None:
        return default
    try:
        ret = int(s)
    except:
        return default
    if ret < 0:
        return default
    return ret

def format_time(nTime):
    import time
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(nTime)))

def format_satoshis(satoshis, chain):
    # XXX Should find COIN and LOG10COIN from chain.
    if satoshis is None:
        return ''
    if satoshis < 0:
        return '-' + format_satoshis(-satoshis, chain)
    satoshis = int(satoshis)
    integer = satoshis / COIN
    frac = satoshis % COIN
    return (str(integer) +
            ('.' + (('0' * LOG10COIN) + str(frac))[-LOG10COIN:])
            .rstrip('0').rstrip('.'))

def format_difficulty(diff):
    idiff = int(diff)
    ret = '.%03d' % (int(round((diff - idiff) * 1000)),)
    while idiff > 999:
        ret = (' %03d' % (idiff % 1000,)) + ret
        idiff = idiff / 1000
    return str(idiff) + ret

def hash_to_address(version, hash):
    if hash is None:
        return 'UNKNOWN'
    vh = version + hash
    return base58.b58encode(vh + util.double_sha256(vh)[:4])

def hash_to_address_link(version, hash, dotdot):
    if hash == DataStore.NULL_PUBKEY_HASH:
        return 'Destroyed'
    if hash is None:
        return 'UNKNOWN'
    addr = hash_to_address(version, hash)
    return ['<a href="', dotdot, 'address/', addr, '">', addr, '</a>']

def decode_check_address(address):
    if ADDRESS_RE.match(address):
        version, hash = decode_address(address)
        if hash_to_address(version, hash) == address:
            return version, hash
    return None, None

def decode_address(addr):
    bytes = base58.b58decode(addr, None)
    if len(bytes) < 25:
        bytes = ('\0' * (25 - len(bytes))) + bytes
    return bytes[:-24], bytes[-24:-4]

def decode_script(script):
    try:
        return deserialize.decode_script(script)
    except KeyError, e:
        return 'Nonstandard script'

def b58hex(b58):
    try:
        return base58.b58decode(b58, None).encode('hex_codec')
    except:
        raise PageNotFound()

def hexb58(hex):
    return base58.b58encode(hex.decode('hex_codec'))

def block_shortlink(block_hash):
    zeroes = 1
    for c in block_hash:
        if c == '0':
            zeroes += 1
        else:
            break
    zeroes &= ~1
    return hexb58("%02x%s" % (zeroes / 2, block_hash[zeroes : zeroes+12]))

def shortlink_block(link):
    try:
        data = base58.b58decode(link, None)
    except:
        raise PageNotFound()
    return ('00' * ord(data[0])) + data[1:].encode('hex_codec')

def short_link(page, link):
    env = page['env'].copy()
    env['SCRIPT_NAME'] = posixpath.normpath(
        posixpath.dirname(env['SCRIPT_NAME'] + env['PATH_INFO'])
        + '/' + page['dotdot'])
    env['PATH_INFO'] = link
    full = wsgiref.util.request_uri(env)
    return ['<p class="shortlink">Short Link: <a href="',
            page['dotdot'], link, '">', full, '</a></p>\n']

def flatten(l):
    if isinstance(l, list):
        return ''.join(map(flatten, l))
    if l is None:
        raise Exception('NoneType in HTML conversion')
    return str(l)

def fix_path_info(env):
    pi = env['PATH_INFO']
    pi = posixpath.normpath(pi)
    if pi[-1] != '/' and env['PATH_INFO'][-1] == '/':
        pi += '/'
    if pi == env['PATH_INFO']:
        return False
    env['PATH_INFO'] = pi
    return True

def redirect(page):
    uri = wsgiref.util.request_uri(page['env'])
    page['start_response'](
        '301 Moved Permanently',
        [('Location', uri),
         ('Content-Type', 'text/html')])
    return ('<html><head><title>Moved</title></head>\n'
            '<body><h1>Moved</h1><p>This page has moved to '
            '<a href="' + uri + '">' + uri + '</a></body></html>')

def serve(store):
    args = store.args
    abe = Abe(store, args)
    if args.host or args.port:
        # HTTP server.
        if args.host is None:
            args.host = "localhost"
        from wsgiref.simple_server import make_server
        port = int(args.port or 80)
        httpd = make_server(args.host, port, abe)
        print "Listening on http://" + args.host + ":" + str(port)
        try:
            httpd.serve_forever()
        except:
            httpd.shutdown()
            raise
    else:
        # FastCGI server.
        from flup.server.fcgi import WSGIServer

        # In the case where the web server starts Abe but can't signal
        # it on server shutdown (because Abe runs as a different user)
        # we arrange the following.  FastCGI script passes its pid as
        # --watch-pid=PID and enters an infinite loop.  We check every
        # minute whether it has terminated and exit when it has.
        wpid = args.watch_pid
        if wpid is not None:
            wpid = int(wpid)
            interval = 60.0  # XXX should be configurable.
            from threading import Timer
            import signal
            def watch():
                if not process_is_alive(wpid):
                    print "process", str(wpid), "terminated, exiting"
                    #os._exit(0)  # sys.exit merely raises an exception.
                    os.kill(os.getpid(), signal.SIGTERM)
                    return
                #print "process", str(wpid), "found alive"
                Timer(interval, watch).start()
            Timer(interval, watch).start()
        WSGIServer(abe).run()

def process_is_alive(pid):
    # XXX probably fails spectacularly on Windows.
    import errno
    try:
        os.kill(pid, 0)
        return True
    except OSError, e:
        if e.errno == errno.EPERM:
            return True  # process exists, but we can't send it signals.
        if e.errno == errno.ESRCH:
            return False # no such process.
        raise

def main(argv):
    conf = {
        "port":         None,
        "host":         None,
        "no_serve":     None,
        "debug":        None,
        "static_path":  None,
        "document_root":None,
        "auto_agpl":    None,
        "download_name":None,
        "watch_pid":    None,

        "template":     DEFAULT_TEMPLATE,
        "template_vars": {
            "ABE_URL": ABE_URL,
            "APPNAME": ABE_APPNAME,
            "VERSION": ABE_VERSION,
            "COPYRIGHT": COPYRIGHT,
            "COPYRIGHT_YEARS": COPYRIGHT_YEARS,
            "COPYRIGHT_URL": COPYRIGHT_URL,
            "DONATIONS_BTC": DONATIONS_BTC,
            "DONATIONS_NMC": DONATIONS_NMC,
            },
        }
    conf.update(DataStore.CONFIG_DEFAULTS)

    args, argv = readconf.parse_argv(argv, conf)
    if not argv:
        pass
    elif argv[0] in ('-h', '--help'):
        print ("""Usage: python -m Abe.abe [-h] [--config=FILE] [--CONFIGVAR=VALUE]...

A Bitcoin block chain browser.

  --help                    Show this help message and exit.
  --version                 Show the program version and exit.
  --print-htdocs-directory  Show the static content directory name and exit.
  --config FILE             Read options from FILE.

All configuration variables may be given as command arguments.
See abe.conf for commented examples.""")
        return 0
    elif argv[0] in ('-v', '--version'):
        print ABE_APPNAME, ABE_VERSION
        print "Schema version", DataStore.SCHEMA_VERSION
        return 0
    elif argv[0] == '--print-htdocs-directory':
        print find_htdocs()
        return 0
    else:
        sys.stderr.write(
            "Error: unknown option `%s'\n"
            "See `python -m Abe.abe --help' for more information.\n"
            % (argv[0],))
        return 1

    conf['serve'] = not conf['no_serve']

    if args.auto_agpl:
        import tarfile

    store = make_store(args)
    if (not args.no_serve):
        serve(store)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
