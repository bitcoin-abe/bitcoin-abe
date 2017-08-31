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

class Myriadcoin(Sha256Chain):
    def __init__(chain, **kwargs):
        chain.name = 'Myriadcoin'
        chain.code3 = 'MYR'
        chain.address_version = '\x32'
        chain.script_addr_vers = '\x09'
        chain.magic = '\xaf\x45\x76\xee'
        Sha256Chain.__init__(chain, **kwargs)

    datadir_conf_file_name = 'myriadcoin.conf'
    datadir_rpcport = 10889
    datadir_p2pport = 10888
