#!/usr/bin/env python

# Retrieved from http://ecdsa.org/ecdsa.py on 2011-10-17.
# Thanks to ThomasV.

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
import daemon

import Abe.DataStore
import Abe.readconf
import operator

# bitcointools -- modified deserialize.py to return raw transaction
import Abe.deserialize
import Abe.util  # Added functions.
import Abe.base58
from Abe.abe import *

AML_APPNAME = "Bitcoin ecdsa.org"

AML_TEMPLATE = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <link rel="stylesheet" type="text/css" href="http://s3.ecdsa.org/style.css" />
    <link rel="shortcut icon" href="http://s3.ecdsa.org/favicon.ico" />
    <title>%(title)s</title>
</head>
<body>
  <div id="logo">
   <a href="%(dotdot)s/">
    <img src="http://s3.ecdsa.org/bc_logo.png" alt="Bitcoin logo" border="none" />
   </a> 
  </div>
  <div id="navigation">
    <ul>
    <li><a href="%(dotdot)shome">Home</a> </li>
    <li><a href="%(dotdot)ssearch">Search</a> </li>
    <li><a href="%(dotdot)sannotate">Annotations</a> </li>
    <li><a href="%(dotdot)swidgets">Widgets</a></li>
    <li><a href="%(dotdot)sthresholdRelease">Threshold release</a></li>
    <li><a href="%(dotdot)sstats.html">Statistics</a></li>
    </ul>
  </div>
  <div id=\"content\">
    <h1>%(h1)s</h1>
    %(body)s
  </div>
</body>
</html>
"""



class Aml(Abe):
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
        abe.home = "home"
        if not args.auto_agpl:
            abe.template_vars['download'] = (
                abe.template_vars.get('download', ''))
        abe.base_url = args.base_url

        abe.reports = abe.get_reports()


    


    def handle_home(abe, page):
        page['title'] = 'Bitcoin Web Services'
        body = page['body']
        body += [  """
<p>This website allows you to :
<ul>
<li>Annotate transactions in the blockchain (signature requested)</li>
<li>Use fundraiser widgets (counters, progress bars, javascript)</li>
<li>Release data when donations to an address reach a given threshold.</li>
</ul>
<br/><br/>
<p style="font-size: smaller">
This site is powered by <span style="font-style: italic"> <a href="https://github.com/bitcoin-abe/bitcoin-abe">bitcoin-ABE</a></span>
&nbsp;&nbsp;source:<a href="ecdsa.py">[1]</a>&nbsp;<a href="abe.diff">[2]</a>
</p>"""
                   ]

         
        return




    def get_sender_comment(abe, tx_id):
        r = abe.store.selectrow("SELECT c_text, c_pubkey, c_sig FROM comments WHERE c_tx = ?""", (tx_id,))
        if r:
            return r[0]
        else:
            return ""

    def get_address_comment(abe, address):
        #rename this column in sql
        r = abe.store.selectrow("SELECT text FROM addr_comments WHERE address = '%s'"""%(address))
        if r:
            return r[0]
        else:
            return ""


    def get_tx(abe, tx_hash ):
        row = abe.store.selectrow("""
        SELECT tx_id, tx_version, tx_lockTime, tx_size
        FROM tx
        WHERE tx_hash = ?
        """, (abe.store.hashin_hex(tx_hash),))
        if row is None: return None, None, None, None
        tx_id, tx_version, tx_lockTime, tx_size = (int(row[0]), int(row[1]), int(row[2]), int(row[3]))
        return tx_id, tx_version, tx_lockTime, tx_size
    

    def get_tx_inputs(abe, tx_id):
        return abe.store.selectall("""
            SELECT
                txin.txin_pos,
                txin.txin_scriptSig,
                txout.txout_value,
                COALESCE(prevtx.tx_hash, u.txout_tx_hash),
                prevtx.tx_id,
                COALESCE(txout.txout_pos, u.txout_pos),
                pubkey.pubkey_hash
              FROM txin
              LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx prevtx ON (txout.tx_id = prevtx.tx_id)
              LEFT JOIN unlinked_txin u ON (u.txin_id = txin.txin_id)
             WHERE txin.tx_id = ?
             ORDER BY txin.txin_pos
             """, (tx_id,))

    def get_tx_outputs(abe, tx_id):
        return abe.store.selectall("""
            SELECT
                txout.txout_pos,
                txout.txout_scriptPubKey,
                txout.txout_value,
                nexttx.tx_hash,
                nexttx.tx_id,
                txin.txin_pos,
                pubkey.pubkey_hash
              FROM txout
              LEFT JOIN txin ON (txin.txout_id = txout.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx nexttx ON (txin.tx_id = nexttx.tx_id)
             WHERE txout.tx_id = ?
             ORDER BY txout.txout_pos
        """, (tx_id,))


    def handle_tx(abe, page):

        tx_hash = wsgiref.util.shift_path_info(page['env'])
        if tx_hash in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        page['title'] = ['Transaction ', tx_hash[:10], '...', tx_hash[-4:]]
        body = page['body']

        if not HASH_PREFIX_RE.match(tx_hash):
            body += ['<p class="error">Not a valid transaction hash.</p>']
            return

        tx_id, tx_version, tx_lockTime, tx_size = abe.get_tx( tx_hash )
        if tx_id is None:
            body += ['<p class="error">Transaction not found.</p>']
            return

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
            pos, script, value, o_hash, o_id, o_pos, binaddr = row

            chain = abe.get_default_chain()
            hash = abe.store.binout(binaddr)
            address = hash_to_address(chain['address_version'], hash)

            return {
                "pos": int(pos),
                "script": abe.store.binout(script),
                "value": None if value is None else int(value),
                "o_hash": abe.store.hashout_hex(o_hash),
                "o_id": o_id,
                "o_pos": None if o_pos is None else int(o_pos),
                "binaddr": abe.store.binout(binaddr),
                }

        def row_to_html(row, this_ch, other_ch, no_link_text):
            body = []
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
                ]
            if row['binaddr'] is None:
                body += ['Unknown', '</td><td></td>']
            else:
                link = hash_to_address_link(chain['address_version'], row['binaddr'], '../')
                addr = hash_to_address(chain['address_version'], row['binaddr'])
                comment = abe.get_address_comment(addr)
                comment += " <a title=\"add comment\" href=\"http://ecdsa.org/annotate?address="+addr+"\">[+]</a>"
                body += [ '<td>', link, '</td><td>', comment, '</td>']
            body += ['</tr>\n']
            return body

        in_rows = map(parse_row, abe.get_tx_inputs(tx_id))
        out_rows = map(parse_row, abe.get_tx_outputs(tx_id))

            

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

        body += abe.short_link(page, 't/' + hexb58(tx_hash[:14]))
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


        sender_comment = abe.get_sender_comment(tx_id)
        sender_comment += " <a href=\"http://ecdsa.org/annotate?tx="+tx_hash+"\">[+]</a>"

        fee = format_satoshis(0 if is_coinbase else (value_in and value_out and value_in - value_out), chain)
        body += [
            len(in_rows),' inputs, ', len(out_rows),' outputs.<br/>\n'
            'Amounts: ', format_satoshis(value_in, chain), ' --> ', format_satoshis(value_out, chain), ' + ',fee,' fee.<br/>\n',
            'Size: ', tx_size, ' bytes<br /><br/>\n',
            '<b>Comment from sender:</b><br/>', sender_comment,  '<br/>\n',
            ]

        body += ['</p>\n',
                 '<a name="inputs"><h3>Inputs</h3></a>\n<table>\n',
                 '<tr><th>Index</th><th>Previous output</th><th>Amount</th>',
                 '<th>From address</th><th>Comment</th></tr>\n']
        for row in in_rows:
            page['body'] += row_to_html(row, 'i', 'o', 'Generation' if is_coinbase else 'Unknown')
        body += ['</table>\n',
                 '<a name="outputs"><h3>Outputs</h3></a>\n<table>\n',
                 '<tr><th>Index</th><th>Redeemed at</th><th>Amount</th>',
                 '<th>To address</th><th>Comment</th></tr>\n']
        for row in out_rows:
            page['body'] += row_to_html(row, 'o', 'i', 'Not yet redeemed')

        body += ['</table>\n']



        def trackrow_to_html(row, report_name):
            line = [ '<tr>\n<td>' ]
            if row['o_hash'] is None:
                line += ['Generation' if is_coinbase else 'Unknown']
            else:
                line += [
                    '<a href="', row['o_hash'], '">', row['o_hash'][:10], '...:', row['o_pos'], '</a>']
                line += [
                    '</td>\n',
                    '<td>', format_satoshis(row['value'], chain), '</td>\n',
                    '<td>']
                if row['binaddr'] is None:
                    line += ['Unknown']
                else:
                    line += hash_to_address_link(chain['address_version'], row['binaddr'], '../')
                    line += [
                        '</td>\n',
                        '<td>', row['dist'].get(report_name),'</td>\n',
                        '<td>', row['comment'],'</td>\n',
                        '</tr>\n']
            return line



    def get_address_out_rows(abe, dbhash):
        return abe.store.selectall("""
            SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                1,
                b.block_hash,
                tx.tx_hash,
                tx.tx_id,
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

    def get_address_in_rows(abe, dbhash):
        return abe.store.selectall("""
            SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                0,
                b.block_hash,
                tx.tx_hash,
                tx.tx_id,
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

    def handle_qr(abe,page):
        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        body = page['body']
        page['title'] = 'Address ' + escape(address)
        version, binaddr = decode_check_address(address)
        if binaddr is None:
            body += ['<p>Not a valid address.</p>']
            return

        ret = """<html><body>
               <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
               <script type="text/javascript" src="http://ecdsa.org/jquery.qrcode.min.js"></script>
               <div id="qrcode"></div>
               <script>jQuery('#qrcode').qrcode("bitcoin:%s");</script>  
               </body></html>"""%address

        abe.do_raw(page, ret)
        page['content_type']='text/html'
        

    def handle_address(abe, page):
        #action = abe.get_param( page, 'action', '')

        address = wsgiref.util.shift_path_info(page['env'])
        if address in (None, '') or page['env']['PATH_INFO'] != '':
            raise PageNotFound()

        body = page['body']
        page['title'] = 'Address ' + escape(address)
        version, binaddr = decode_check_address(address)
        if binaddr is None:
            body += ['<p>Not a valid address.</p>']
            return

        txpoints = []
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

        dbhash = abe.store.binin(binaddr)
        rows = []
        rows += abe.get_address_out_rows( dbhash )
        rows += abe.get_address_in_rows( dbhash )
        #rows.sort()

        for row in rows:
            nTime, chain_id, height, is_in, blk_hash, tx_hash, tx_id, pos, value = row
            txpoint = {
                    "nTime":    int(nTime),
                    "chain_id": int(chain_id),
                    "height":   int(height),
                    "is_in":    int(is_in),
                    "blk_hash": abe.store.hashout_hex(blk_hash),
                    "tx_hash":  abe.store.hashout_hex(tx_hash),
                    "tx_id":    int(tx_id),
                    "pos":      int(pos),
                    "value":    int(value),
                    }
            adj_balance(txpoint)
            txpoints.append(txpoint)

        #txpoints.sort( lambda a,b: a['tx_id']<b['tx_id'])
        txpoints = sorted(txpoints, key=operator.itemgetter("tx_id"))

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


        comment = abe.get_address_comment(address)
        comment += " <a title=\"add comment\" href=\"http://ecdsa.org/annotate?address="+address+"\">[+]</a>"
            
        body += [ '<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>',
                  '<script type="text/javascript" src="http://ecdsa.org/jquery.qrcode.min.js"></script>',
                  '<div style="float:right;" id="qrcode"></div>',
                  "<script>jQuery('#qrcode').qrcode(\"bitcoin:"+address+"\");</script>"  ]


        body += abe.short_link(page, 'a/' + address[:10])
        body += ['<p>Balance: '] + format_amounts(balance, True)

        for chain_id in chain_ids:
            balance[chain_id] = 0  # Reset for history traversal.

        body += ['<br />\n',
                 'Transactions in: ', count[0], '<br />\n',
                 'Received: ', format_amounts(received, False), '<br />\n',
                 'Transactions out: ', count[1], '<br />\n',
                 'Sent: ', format_amounts(sent, False), '<br/>'
                 'Comment: ', comment, '<br/>'
                 ]

        body += ['</p>\n'
                 '<h3>Transactions</h3>\n'
                 '<table>\n<tr><th>Transaction</th><th>Block</th>'
                 '<th>Approx. Time</th><th>Amount</th><th>Balance</th>'
                 '<th>Comment</th>'
                 '</tr>\n']

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
                body += ['<span style="color:red;">-', format_satoshis(-elt['value'], chain), "</span>" ]
            else:
                body += ['+', format_satoshis(elt['value'], chain)]

            # get sender comment 
            comment = abe.get_sender_comment(elt['tx_id'])
            comment += " <a href=\"http://ecdsa.org/annotate?tx="+elt['tx_hash']+"\">[+]</a>"

            body += ['</td><td>',
                     format_satoshis(balance[elt['chain_id']], chain),
                     '</td><td>', comment,
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

    def get_reports(abe):
        rows = abe.store.selectall("select reports.report_id, tx.tx_id, tx.tx_hash, name from reports left join tx on tx.tx_id=reports.tx_id" )
        return map(lambda x: { 'report_id':int(x[0]), 'tx_id':int(x[1]), 'tx_hash':x[2], 'name':x[3] }, rows)

    def handle_reports(abe, page):
        page['title'] =  'Fraud reports'
        page['body'] += [ 'List of transactions that have been reported as fraudulent.', '<br/><br/>']
        page['body'] += [ '<table><tr><th>name</th><th>transaction</th></tr>']
        for item in abe.reports:
            link = '<a href="tx/' + item['tx_hash'] + '">'+ item['tx_hash'] + '</a>'
            page['body'] += ['<tr><td>'+item['name']+'</td><td>'+link+'</td></tr>']
        page['body'] += [ '</table>']

    def handle_annotate(abe, page):
        tx_hash = (page['params'].get('tx') or [''])[0]
        address = (page['params'].get('address') or [''])[0]
        message = (page['params'].get('comment') or [''])[0]
        signature = (page['params'].get('signature') or [''])[0]

        if not tx_hash and not address:
            page['title'] =  'Annotations'
            page['body'] += [ 'This website allows you to annotate the Bitcoin blockchain.<br/><br/>',
                              'You will need a version of bitcoind that has the "signmessage" command.<br/>'
                              'In order to annotate an address or transaction, first <a href="search">find</a> the corresponding page, then follow the "[+]" link. <a href="http://ecdsa.org/annotate?tx=e357fece18a4191be8236570c7dc309ec6ac04473317320b5e8b9ab7cd023549">(example here)</a><br/><br/>']
            
            page['body'] += [ '<h3>Annotated addresses.</h3>']
            rows = abe.store.selectall("""select text, address from addr_comments limit 100""" )
            page['body'] += [ '<table>']
            page['body'] += [ '<tr><th>Address</th><th>Comment</th></tr>']
            for row in rows:
                link = '<a href="address/' + row[1]+ '">'+ row[1] + '</a>'
                page['body'] += ['<tr><td>'+link+'</td><td>'+row[0]+'</td></tr>']
            page['body'] += [ '</table>']


            page['body'] += [ '<h3>Annotated transactions.</h3>']
            rows = abe.store.selectall("""select tx.tx_id, tx.tx_hash, comments.c_text 
                                          from comments left join tx on tx.tx_id = comments.c_tx where c_sig != '' limit 100""" )
            page['body'] += [ '<table>']
            page['body'] += [ '<tr><th>Transaction</th><th>Comment</th></tr>']
            for row in rows:
                link = '<a href="tx/' + row[1]+ '">'+ row[1] + '</a>'
                page['body'] += ['<tr><td>'+link+'</td><td>'+row[2]+'</td></tr>']
            page['body'] += [ '</table>']
            return

        if tx_hash:

            page['title'] =  'Annotate transaction'
            tx_id, b, c, d = abe.get_tx( tx_hash )
            chain = abe.get_default_chain()

            in_addresses = []
            for row in abe.get_tx_inputs( tx_id ):
                addr =  abe.store.binout(row[6])
                addr = hash_to_address_link(chain['address_version'], addr, '../')
                in_addresses.append( addr[3] )
            if not address:
                address = in_addresses[0]

            out_addresses = []
            for row in abe.get_tx_outputs( tx_id ):
                addr =  abe.store.binout(row[6])
                addr = hash_to_address_link(chain['address_version'], addr, '../')
                out_addresses.append( addr[3] )

            if message or signature:
                # check address
                #if address not in in_addresses and address not in out_addresses:
                if address not in in_addresses:
                    page['title'] = 'Error'
                    page['body'] = ['<p>wrong address for this transaction.</p>\n']
                    print address, in_addresses
                    return

                # check signature
                import bitcoinrpc
                conn = bitcoinrpc.connect_to_local()
                message = message.replace("\r\n","\\n").replace("!","\\!").replace("$","\\$")
                print "verifymessage:", address, signature, repr(message)
                try:
                    v = conn.verifymessage(address,signature, tx_hash+":"+message)
                except:
                    v = False
                if not v:
                    page['title'] = 'Error'
                    page['body'] = ['<p>Invalid signature.</p>']
                    return

                # little bobby tables
                message = message.replace('"', '\\"').replace("'", "\\'")
                # escape html 
                message = escape( message )
                message = message[:1024]

                row = abe.store.selectrow("select c_tx from comments where c_tx=%d "%(tx_id ) )
                if not row:
                    abe.store.sql("insert into comments (c_tx, c_text, c_pubkey, c_sig) VALUES (%d, '%s', '%s', '%s')"%( tx_id, message, address, signature) )
                    abe.store.commit()
                    page['body'] = ['<p>Your comment was added successfully.</p>\n']
                else:
                    if not message:
                        abe.store.sql("delete from comments where c_tx=%d "%( tx_id ) )
                        abe.store.commit()
                        page['body'] = ['<p>Your comment was deleted.</p>\n']
                    else:
                        abe.store.sql("update comments set c_text='%s', c_sig='%s', c_pubkey='%s' where c_tx=%d "%( message, signature, address, tx_id ) )
                        abe.store.commit()
                        page['body'] = ['<p>Your comment was updated.</p>\n']
                return
            else:
                select = "<select id=\"address\" onkeyup=\"change_address(this.value);\" onchange=\"change_address(this.value);\" name='address'>" \
                    + "\n".join( map( lambda addr: "<option value=\""+addr+"\">"+addr+"</option>", in_addresses ) ) \
                    +"</select>"
                select = select.replace("<option value=\""+address+"\">","<option value=\""+address+"\" selected>")
                tx_link = '<a href="tx/' + tx_hash + '">'+ tx_hash + '</a>'

                javascript = """
            <script>
               function change_address(x){ 
                 document.getElementById("saddress").innerHTML=x;
               }
               function change_text(x){ 
                 x = x.replace(/!/g,"\\\\!");
                 x = x.replace(/\\n/g,"\\\\n");
                 x = x.replace(/\\$/g,"\\\\$");
                 document.getElementById("stext").innerHTML = x; 
               }
               function onload(){
                 change_text(document.getElementById("text").value);
                 //change_address(document.getElementById("address").value);
               }
            </script>
            """

                page['title'] = 'Annotate transaction'
                page['body'] = [
                    javascript,
                    '<form id="form" action="', page['dotdot'], 'annotate">\n'
                    'Transaction: ',tx_link,'<br/>'
                    'Address:', select,'<br/><br/>\n'
                    'Message:<br/><textarea id="text" onkeyup="change_text(this.value);" name="comment" cols="80" value=""></textarea><br/><br/>\n'
                    'You must sign your message with one of the input addresses of involved in the transaction.<br/>\n'
                    'The signature will be returned by the following command line:<br/>\n'
                    '<pre>bitcoind signmessage <span id="saddress">'+in_addresses[0]+'</span> "'+tx_hash+':<span id="stext">your text</span>"</pre>\n'
                    'Signature:<br/><input name="signature" value="" style="width:500px;"/><br/>'
                    '<input name="tx" type="hidden" value="'+tx_hash+'" />'
                    '<button type="submit">Submit</button>\n'
                    '</form>\n']
            return
        

    
        if address:
            page['title'] =  'Annotate address'

            if message or signature:
                # check signature
                import bitcoinrpc
                conn = bitcoinrpc.connect_to_local()
                message = message.replace("\n","\\n").replace("!","\\!").replace("$","\\$")
                print "verifymessage:", address, signature, message
                try:
                    v = conn.verifymessage(address,signature, message)
                except:
                    v = False
                if not v:
                    page['title'] = 'Error'
                    page['body'] = ['<p>Invalid signature.</p>']
                    return

                # little bobby tables
                message = message.replace('"', '\\"').replace("'", "\\'")
                # escape html 
                message = escape( message )
                message = message[:1024]

                row = abe.store.selectrow("select address from addr_comments where address='%s' "%(address ) )
                if not row:
                    abe.store.sql("insert into addr_comments (address, text) VALUES ('%s', '%s')"%( address, message) )
                    abe.store.commit()
                    page['body'] = ['<p>Your comment was added successfully.</p>\n']
                else:
                    if not message:
                        abe.store.sql("delete from addr_comments where address='%s' "%( message ) )
                        abe.store.commit()
                        page['body'] = ['<p>Your comment was deleted.</p>\n']
                    else:
                        abe.store.sql("update addr_comments set text='%s' where address='%s' "%( message, address ) )
                        abe.store.commit()
                        page['body'] = ['<p>Your comment was updated.</p>\n']
                return
            else:
                javascript = """
            <script>
               function change_text(x){ 
                 x = x.replace(/!/g,"\\\\!");
                 x = x.replace(/\\n/g,"\\\\n");
                 x = x.replace(/\\$/g,"\\\\$");
                 document.getElementById("stext").innerHTML=x; 
               }
               function onload(){
                 change_text(document.getElementById("text").value);
               }
            </script>
            """

                page['title'] = 'Annotate address'
                page['body'] = [
                    javascript,
                    '<form id="form" action="', page['dotdot'], 'annotate">\n'
                    'Address:', address,'<br/><br/>\n'
                    'Message:<br/><textarea id="text" onkeyup="change_text(this.value);" name="comment" cols="80" value=""></textarea><br/><br/>\n'
                    'You must sign your message with the addresses.<br/>\n'
                    'The signature will be returned by the following command line:<br/>\n'
                    '<pre>bitcoind signmessage <span id="saddress">'+address+'</span> "<span id="stext">your text</span>"</pre>\n'
                    'Signature:<br/><input name="signature" value="" style="width:500px;"/><br/>'
                    '<input name="address" type="hidden" value="'+address+'" />'
                    '<button type="submit">Submit</button>\n'
                    '</form>\n']



    def handle_thresholdRelease(abe, page):
        page['title'] =  'Threshold Release'
        chain = abe.get_default_chain()

        target = (page['params'].get('target') or [''])[0]
        address = (page['params'].get('address') or [''])[0]
        secret   = (page['params'].get('secret') or [''])[0]
        signature = (page['params'].get('signature') or [''])[0]
        
        if address:
            # check if address is valid
            version, binaddr = decode_check_address(address)
            if binaddr is None:
                page['body'] = ['<p>Not a valid address.</p>']
                return
            # check amount
            try:
                target = float(target)
            except:
                page['body'] = ['<p>Not a valid amount.</p>']
                return
            # check signature
            import bitcoinrpc
            conn = bitcoinrpc.connect_to_local()
            print address, signature
            try:
                v = conn.verifymessage(address,signature, "fundraiser")
            except:
                v = False
            if not v:
                page['body'] = ['<p>Invalid signature.</p>']
                return

            # little bobby tables
            secret = secret.replace('"', '\\"').replace("'", "\\'")
            # escape html 
            #message = escape( message )
            #
            secret = secret[:1024]

            row = abe.store.selectrow("select address from fundraisers where address='%s'"%(address ) )
            if not row:
                abe.store.sql("insert into fundraisers (address, target, secret) VALUES ('%s', %d, '%s')"%( address, target, secret) )
                abe.store.commit()
                page['body'] = ['<p>Your fundraiser was added successfully.</p>\n']
            else:
                if not secret:
                    abe.store.sql("delete from fundraisers where address='%s'"%( address ) )
                    abe.store.commit()
                    page['body'] = ['<p>Fundraiser entry was deleted.</p>\n']
                else:
                    abe.store.sql("update fundraisers set target=%d, secret='%s' where address='%s'"%( target, secret, address ) )
                    abe.store.commit()
                    page['body'] = ['<p>Your fundraiser data was updated.</p>\n']

            msg = "<object data=\"http://ecdsa.org/fundraiser/"+address+"?width=400\" height=\"60\" width=\"400\">Donate to "+address+"</object/>"

            page['body'] += "Sample code:<br/><pre>"+escape(msg)+"</pre><br/><br/>"+msg
            return
        else:
            javascript = """
            <script>
               function change_address(x){ 
                 //check validity here
                 document.getElementById("saddress").innerHTML=x;
               }
               function onload(){
                 change_address(document.getElementById("address").value);
               }
            </script>
            """
            msg= """
This service allows you to release digital content when a requested amount of Bitcoin donations has been reached.<br/>
<br/>
For example, you may want to publish a low quality version of a music file, and release a high quality version only if donations reach the price you want.<br/>
<br/>
There are various ways to use this service:
<ul>
<li>You may upload your content at a private URL; we will disclose the URL once the amount is reached.</li>
<li>You may encrypt your content and upload it to a public server; we will publish the encryption password only when the target amount is reached.</li>
</ul>
Once the threshold is reached, the content is displayed in place of the donation progress bar.<br/>
<br/>
"""

            page['title'] = 'Threshold Release'
            page['body'] = [
                javascript, msg,
                '<form id="form" action="', page['dotdot'], 'thresholdRelease">\n'
                'Address:<br/><input name="address" value="" style="width:500px;" onkeyup="change_address(this.value);"/><br/><br/>'
                'Target amount:<br/><input name="target" value="" style="width:500px;"/><br/><br/>'
                'Secret (will be displayed in place of the widget when the donation target is reached. Html, max. 1024 bytes):<br/>'
                '<textarea name="secret" value="" style="width:500px;"></textarea><br/><br/>'
                'You must provide a signature in order to demonstrate that you own the bitcoin address of the fundraiser.<br/>'
                'The signature will be returned by the following command line:<br/>\n'
                '<pre>bitcoind signmessage <span id="saddress"></span> <span id="stext">fundraiser</span></pre>\n'
                'Signature:<br/><input name="signature" value="" style="width:500px;"/><br/>'
                '<button type="submit">Submit</button>\n'
                '</form>\n'
                ]
    # check and display html as it is typed


    def get_fundraiser(abe,page):
        address = page['env'].get('PATH_INFO')[1:]
        if not address: return None,None,None,None
        chain = abe.get_default_chain()
        # get donations
        donations = abe.q_getreceivedbyaddress(page,chain)
        try:
            donations = float(donations)
        except:
            donations = 0
        # check if address is in the database
        row = abe.store.selectrow("select target, secret from fundraisers where address='%s'"%address ) 
        secret = None
        target = None
        if row: 
            target, secret = row
            if donations < target: secret = None
            target = float(target)

        #priority
        try:
            target = float( page['params'].get('target')[0] )
        except:
            pass

        return address, donations, target, secret


    def handle_fundraiser_js(abe,page):
        """ return a scriptlet"""
        address,donations,target,secret = abe.get_fundraiser(page)
        if secret:
            secret = escape( secret )
        ret = "var fundraiser_address = \"%s\";\nvar fundraiser_secret='%s';\nvar fundraiser_received = %f;\nfundraiser_callback();\n"%(address,secret,donations)
        abe.do_raw(page, ret)
        page['content_type']='text/javascript'


    def handle_fundraiser_img(abe,page):
        return abe.handle_counter(page)        

    def handle_counter(abe,page):
        """ return a png with percentage"""
        address, donations, target, secret = abe.get_fundraiser(page)
        if target:

            progress = int(100 * donations/target)
            progress = max(0, min( progress, 100 ))
            return abe.serve_static("percent/%dpercent.png"%progress, page['start_response'])

        else:
            donations = "%.2f"%donations
            path = "/img/" + donations + ".png"
            cpath = abe.htdocs + path
            if not os.path.exists(cpath):
                s = donations+ " BTC"
                length = 13*len(s)
                cmd = "echo \"%s\" | convert -page %dx20+0+0 -font Helvetica -style Normal -background none -undercolor none -fill black -pointsize 22 text:- +repage -background none -flatten %s"%(s, length, cpath)
                print cmd
                os.system(cmd)

            return abe.serve_static(path, page['start_response'])




    def get_param(abe,page,name,default):
        try:
            return page['params'].get(name)[0] 
        except:
            return default


    def handle_fundraiser(abe, page):
        abe.handle_widgets(page)

    def handle_widgets(abe, page):
        """ return embedded html"""
        address, donations, target, secret = abe.get_fundraiser(page)
        if not address:
            f = open(abe.htdocs + '/widgets.html', "rb")
            s = f.read()
            f.close()
            page['body'] = s
            page['title'] = "Bitcoin Widgets"
            return

        if secret: 
            abe.do_raw(page, secret)
            page['content_type']='text/html'
            return

        try:
            width = int(page['params'].get('width')[0])
        except:
            width = 400
        try:
            bg = page['params'].get('bg')[0] 
        except:
            bg = "#000000"
        try:
            lc = page['params'].get('leftcolor')[0] 
        except:
            lc = "#dddddd"
        try:
            rc = page['params'].get('rightcolor')[0] 
        except:
            rc = "#ffaa44"
        try:
            padding = page['params'].get('padding')[0] 
        except:
            padding = "3"
        try:
            radius = page['params'].get('radius')[0] 
        except:
            radius = "1em"
        try:
            textcolor = page['params'].get('textcolor')[0] 
        except:
            textcolor = "#000000"

        leftwidth = width - 120

        if target:
            progress = min( width, max( 1, int( leftwidth * donations/target ) ))
            percent = min( 100, max( 0, int( 100 * donations/target ) ))
            title = "%d"%percent + " percent of %.2f BTC"%target
        else:
            title = ""
            progress = leftwidth

        outer_style = "border-radius:%s; -moz-border-radius:%s; padding:%s; color:%s; background-color: %s;"%(radius,radius,padding,textcolor,bg)
        left_style  = "border-radius:%s; -moz-border-radius:%s; padding:%s; background-color: %s;"%(radius,radius,padding,lc)
        right_style = "border-radius:%s; -moz-border-radius:%s; padding:%s; background-color: %s; width:80px; text-align:center;"%(radius,radius,padding,rc)

        count = "%.2f&nbsp;BTC"%donations
        link_count = "<a style=\"text-decoration:none;color:"+textcolor + "\" title=\""+ title + "\" href=\"http://ecdsa.org/address/"+address+"\" target=\"_blank\">"+count+"</a>"

        text = "Donate"
        link_text  = "<a style=\"text-decoration:none;color:"+textcolor+"\" href=\"javascript:alert('Donate to this Bitcoin address:\\n"+address+"');\">"+text+"</a>"
        ret = """<table style="border-width:0px;"><tr><td>
 <table style="%s width:%dpx;">
  <tr><td style="%s width:%dpx; text-align:center;">%s</td><td></td></tr>
 </table>
</td>
<td>
 <table style="%s width:100px;">
   <tr><td style="%s">%s</td></tr>
 </table>
</td></tr></table>"""%(outer_style,leftwidth,left_style,progress,link_count,outer_style,right_style,link_text)

        abe.do_raw(page, ret)
        page['content_type']='text/html'




def serve(store):
    args = store.args
    abe = Aml(store, args)

    if args.host or args.port:
        # HTTP server.
        if args.host is None:
            args.host = "localhost"
        from wsgiref.simple_server import make_server
        port = int(args.port or 80)
        httpd = make_server(args.host, port, abe )
        print "Listening on http://" + args.host + ":" + str(port)
        try:
            httpd.serve_forever()
        except:
            httpd.shutdown()
            raise



from daemon import Daemon

class MyDaemon(Daemon):
    def __init__(self,args):
        self.args = args
        Daemon.__init__(self, self.args.pidfile, stderr=self.args.error_log, stdout=self.args.access_log )

    def run(self):
        store = make_store(self.args)
        serve(store)


if __name__ == '__main__':

    cmd = sys.argv[1]
    if cmd not in ['start','stop','restart','run']:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)

    argv = sys.argv[2:]

    conf = {
        "port": 80,
        "host": '',
        "no_serve":     None,
        "debug":        None,
        "static_path":  None,
        "auto_agpl":    None,
        "download_name":None,
        "watch_pid":    None,
        "base_url":     None,
        "no_update":    None,
        "pidfile":      '',
        "access_log":   '',
        "error_log":    '',
        "document_root":'',
        "template":     AML_TEMPLATE,
        "template_vars": {
            "APPNAME": AML_APPNAME,
            "CONTENT_TYPE": 'text/html',
            },
        }

    conf.update(DataStore.CONFIG_DEFAULTS)
    argv.append('--config=/etc/abe.conf')
    args, argv = readconf.parse_argv(argv, conf)
    if argv:
        sys.stderr.write("Error: unknown option `%s'\n" % (argv[0],))
        sys.exit(1)

    daemon = MyDaemon(args)
    if cmd == 'start' :
        daemon.start()
    elif cmd == 'stop' :
        daemon.stop()
    elif cmd == 'restart' :
        daemon.restart()
    elif cmd=='run':
        daemon.stop()
        daemon.run()

    sys.exit(0)
