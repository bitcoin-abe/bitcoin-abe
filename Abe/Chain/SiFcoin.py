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

from .SiFChain import SiFChain
class SiFcoin(SiFChain):
    """
    A blockchain that hashes block headers using the SiF algorithm.
    The current implementation requires the sifcoin_hash module.
    """
    def __init__(chain, **kwargs):
        chain.name = "SiFcoin"
        chain.code3 = "SIC"
        chain.policy = "SiFChain"
        chain.address_version = "\x07"
        chain.script_addr_vers = "\x05"
        chain.magic = "\xf2\xd5\xd3\xd8"
        SiFChain.__init__(chain, **kwargs)


    datadir_conf_file_name = 'sifcoin.conf'
    datadir_rpcport = 8372
    datadir_p2pport = 9999

