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

from .Sha256NmcAuxPowChain import Sha256NmcAuxPowChain
from . import SCRIPT_TYPE_UNKNOWN
from ..deserialize import opcodes


class Namecoin(Sha256NmcAuxPowChain):
    """
    Namecoin represents name operations in transaction output scripts.
    """

    def __init__(self, **kwargs):
        self.name = "Namecoin"
        self.code3 = "NMC"
        self.address_version = "\x34"
        self.magic = "\xf9\xbe\xb4\xfe"
        Sha256NmcAuxPowChain.__init__(self, **kwargs)

    _drops = (opcodes.OP_NOP, opcodes.OP_DROP, opcodes.OP_2DROP)

    def parse_decoded_txout_script(self, decoded):
        start = 0
        pushed = 0

        # Tolerate (but ignore for now) name operations.
        for i in range(len(decoded)):
            opcode = decoded[i][0]

            if (
                decoded[i][1] is not None
                or opcode == opcodes.OP_0
                or opcode == opcodes.OP_1NEGATE
                or (opcode >= opcodes.OP_1 and opcode <= opcodes.OP_16)
            ):
                pushed += 1
            elif opcode in self._drops:
                to_drop = self._drops.index(opcode)
                if pushed < to_drop:
                    break
                pushed -= to_drop
                start = i + 1
            else:
                return Sha256NmcAuxPowChain.parse_decoded_txout_script(
                    self, decoded[start:]
                )

        return SCRIPT_TYPE_UNKNOWN, decoded

    datadir_conf_file_name = "namecoin.conf"
    datadir_rpcport = 8336
