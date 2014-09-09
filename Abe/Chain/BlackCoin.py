# Copyright(C) 2014 by Abe developers.

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

from .NvcChain import NvcChain

class BlackCoin(NvcChain):
    def __init__(chain, **kwargs):
        chain.name = "BlackCoin"
        chain.code3 = "BC"
        chain.address_version = "\x19"
        chain.script_addr_vers = "\x55"
        chain.magic = "\x70\x35\x22\x05"
        NvcChain.__init__(chain, **kwargs)

    def block_header_hash(chain, header):
        b = chain.parse_block_header(header)
        if (b['version'] > 6):
            from .. import util
            return util.double_sha256(header)
        import ltc_scrypt
        return ltc_scrypt.getPoWHash(header)

    datadir_conf_file_name = "blackcoin.conf"
    datadir_rpcport = 15715
