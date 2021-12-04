# Copyright(C) 2014 by Abe developers.

"""test_util.py: test Abe utility functions"""

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

from Abe import util


def test_calculate_target_004c792d() -> None:
    """test_calculate_target_004c792d"""
    assert util.calculate_target(0x004C792D) == 0


def test_calculate_target_1d00ffff() -> None:
    """test_calculate_target_1d00ffff"""
    assert (
        util.calculate_target(0x1D00FFFF)
        == 0xFFFF0000000000000000000000000000000000000000000000000000
    )


def test_calculate_target_1c00800e() -> None:
    """test_calculate_target_1c00800e"""
    assert (
        util.calculate_target(0x1C00800E)
        == 0x800E00000000000000000000000000000000000000000000000000
    )


def test_calculate_target_1b0e7256() -> None:
    """test_calculate_target_1b0e7256"""
    assert (
        util.calculate_target(0x1B0E7256)
        == 0xE7256000000000000000000000000000000000000000000000000
    )


def test_calculate_target_1b0098fa() -> None:
    """test_calculate_target_1b0098fa"""
    assert (
        util.calculate_target(0x1B0098FA)
        == 0x98FA000000000000000000000000000000000000000000000000
    )


def test_calculate_target_1a6a93b3() -> None:
    """test_calculate_target_1a6a93b3"""
    assert (
        util.calculate_target(0x1A6A93B3)
        == 0x6A93B30000000000000000000000000000000000000000000000
    )


def test_calculate_target_1a022fbe() -> None:
    """test_calculate_target_1a022fbe"""
    assert (
        util.calculate_target(0x1A022FBE)
        == 0x22FBE0000000000000000000000000000000000000000000000
    )


def test_calculate_target_1900896c() -> None:
    """test_calculate_target_1900896c"""
    assert (
        util.calculate_target(0x1900896C)
        == 0x896C00000000000000000000000000000000000000000000
    )


def test_calculate_target_1e0fffff() -> None:
    """test_calculate_target_1e0fffff"""
    assert (
        util.calculate_target(0x1E0FFFFF)
        == 0xFFFFF000000000000000000000000000000000000000000000000000000
    )


def test_calculate_target_1f123456() -> None:
    """test_calculate_target_1f123456"""
    assert (
        util.calculate_target(0x1F123456)
        == 0x12345600000000000000000000000000000000000000000000000000000000
    )


def test_calculate_target_80555555() -> None:
    # pylint: disable=line-too-long
    """test_calculate_target_80555555"""
    assert (
        util.calculate_target(0x80555555)
        == 0x5555550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    )


def test_calculate_target_00777777() -> None:
    """test_calculate_target_00777777"""
    assert util.calculate_target(0x00777777) == 0x0


def test_calculate_target_01cccccc() -> None:
    """test_calculate_target_01cccccc"""
    assert util.calculate_target(0x01CCCCCC) == -0x4C


def test_calculate_target_02666666() -> None:
    """test_calculate_target_02666666"""
    assert util.calculate_target(0x02666666) == 0x6666


def test_calculate_target_03aaaaaa() -> None:
    """test_calculate_target_03aaaaaa"""
    assert util.calculate_target(0x03AAAAAA) == -0x2AAAAA
