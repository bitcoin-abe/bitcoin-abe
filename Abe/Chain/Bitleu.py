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

from .ScryptJaneChain import ScryptJaneChain
from .PpcPosChain import PpcPosChain

class Bitleu(ScryptJaneChain, PpcPosChain):
    def __init__(chain, **kwargs):
        chain.name = 'Bitleu'
        chain.code3 = 'BTL'
        chain.address_version = "\x30"
        chain.script_addr_vers = '\x1b'
        chain.magic = "\xd9\xe6\xe7\xe5"
        chain.decimals = 6
        super(Bitleu, chain).__init__(**kwargs)

    datadir_conf_file_name = "Bitleu.conf"
    datadir_rpcport = 7997
    start_time = 1394480376
