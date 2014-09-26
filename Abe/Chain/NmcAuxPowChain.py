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

from . import BaseChain
from .. import deserialize

class NmcAuxPowChain(BaseChain):
    """
    A blockchain that represents merge-mining proof-of-work in an "AuxPow" structure as does Namecoin.
    """
    def __init__(chain, **kwargs):
        BaseChain.__init__(chain, **kwargs)

    def ds_parse_block_header(chain, ds):
        d = BaseChain.ds_parse_block_header(chain, ds)
        if d['version'] & (1 << 8):
            d['auxpow'] = deserialize.parse_AuxPow(ds)
        return d

    def has_feature(chain, feature):
        return feature == 'block_version_bit8_merge_mine' \
            or BaseChain.has_feature(chain, feature)
