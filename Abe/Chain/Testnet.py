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


class Testnet(Sha256Chain):
    """
    The original bitcoin test blockchain.
    """

    def __init__(self, **kwargs):
        self.name = "Testnet"
        self.code3 = "BC0"
        self.address_version = "\x6f"
        self.script_addr_vers = "\xc4"
        self.magic = "\xfa\xbf\xb5\xda"
        super().__init__(**kwargs)

    # XXX
    # datadir_conf_file_name = "bitcoin.conf"
    # datadir_rpcport = 8332
