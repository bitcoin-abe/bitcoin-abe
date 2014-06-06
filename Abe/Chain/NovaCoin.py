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

class NovaCoin(NvcChain):
    def __init__(chain, **kwargs):
        chain.name = 'NovaCoin'
        chain.code3 = 'NVC'
        chain.address_version = "\x08"
        chain.magic = "\xe4\xe8\xe9\xe5"
        chain.decimals = 6
        NvcChain.__init__(chain, **kwargs)

    datadir_conf_file_name = "novacoin.conf"
    datadir_rpcport = 8344
