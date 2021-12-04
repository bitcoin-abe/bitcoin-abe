# Copyright(C) 2014 by Abe developers.

"""conftest.py: pytest session-scoped objects"""

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

from typing import Optional
from pytest import fixture, FixtureRequest
from . import db
from .db import DataBasetype


@fixture(scope="session", params=db.testdb_params())
def db_server(request: FixtureRequest) -> Optional[DataBasetype]:
    """Database Server to be used in tests"""
    server = db.create_server(request.param)  # type:ignore
    if server is not None:
        request.addfinalizer(server.delete)
    return server
