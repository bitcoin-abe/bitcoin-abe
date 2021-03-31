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

class TagCoin(NvcChain):
    def __init__(chain, **kwargs):
        chain.name = 'TagCoin'
        chain.code3 = 'TAG'
        chain.address_version = "\x41"
        chain.script_addr_vers = '\x08'
        chain.magic = "\xf4\xed\xe2\xb9"
        chain.decimals = 6
        NvcChain.__init__(chain, **kwargs)

    datadir_conf_file_name = "TagCoin.conf"
    datadir_rpcport = 9624
    datadir_p2pport = 8623
