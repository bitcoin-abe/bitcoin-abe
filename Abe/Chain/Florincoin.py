# Copyright(C) 2015 by Abe developers.

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

from . import BaseChain
from .. import util, deserialize

class Florincoin(BaseChain):
    """
    Florincoin
    """
    def __init__(self, **kwargs):
        self.name = 'Florincoin'
        self.code3 = 'FLO'
        self.magic = "\u00fd\u00c0\u00a5\u00f1"
        BaseChain.__init__(self, **kwargs)

    @staticmethod
    def block_header_hash(header):
        return util.double_sha256(header)

    def ds_parse_transaction(chain, ds):
        return deserialize.parse_Transaction(ds, has_tx_comment=True)
