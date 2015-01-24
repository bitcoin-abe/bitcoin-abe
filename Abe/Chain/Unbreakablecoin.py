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

from .Sha256Chain import Sha256Chain

class Unbreakablecoin(Sha256Chain):
    def __init__(chain, **kwargs):
        chain.name = 'Unbreakablecoin'
        chain.code3 = 'UNB'
        chain.address_version = '\x00'
        chain.script_addr_vers = '\x05'
        chain.magic = '\x83\x33\x07\xb1'
        Sha256Chain.__init__(chain, **kwargs)

    datadir_conf_file_name = 'Unbreakablecoin.conf'
    datadir_rpcport = 9337
    datadir_p2pport = 9336
