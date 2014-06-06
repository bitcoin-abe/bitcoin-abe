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

YAC_START_TIME = 1377557832

class ScryptJaneChain(BaseChain):
    """
    A blockchain that uses Scrypt-Jane to hash block headers.
    The current implementation requires the yac_scrypt module.
    The ScryptJaneChain policy must be subclassed to provide the start_time
    parameter in Unix time_t format.
    """

    POLICY_ATTRS = BaseChain.POLICY_ATTRS + ['start_time']

    def block_header_hash(chain, header):
        import yac_scrypt
        b = chain.parse_block_header(header)
        return yac_scrypt.getPoWHash(header, b['nTime'] + YAC_START_TIME - chain.start_time)
