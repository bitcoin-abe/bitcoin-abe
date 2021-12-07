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
"""
Module containing all of the specific chain data for all of the supported blockchains
"""
from typing import List
from . import utils
from .chains import *
from .base_chain import (
    PolicyAttrs,
    BaseChain,
    SCRIPT_TYPE_INVALID,
    SCRIPT_TYPE_UNKNOWN,
    SCRIPT_TYPE_PUBKEY,
    SCRIPT_TYPE_ADDRESS,
    SCRIPT_TYPE_BURN,
    SCRIPT_TYPE_MULTISIG,
    SCRIPT_TYPE_P2SH,
)


__all__ = [
    "utils",
    "create",
    "CHAIN_CONFIG",
    "BaseChain",
    "SCRIPT_TYPE_INVALID",
    "SCRIPT_TYPE_UNKNOWN",
    "SCRIPT_TYPE_PUBKEY",
    "SCRIPT_TYPE_ADDRESS",
    "SCRIPT_TYPE_BURN",
    "SCRIPT_TYPE_MULTISIG",
    "SCRIPT_TYPE_P2SH",
]


CHAIN_CONFIG: List[PolicyAttrs] = [
    {"chain": "Bitcoin"},
    {"chain": "Testnet"},
    {"chain": "Namecoin"},
    {
        "chain": "Weeds",
        "policy": "Sha256Chain",
        "code3": "WDS",
        "address_version": b"\xf3",
        "magic": b"\xf8\xbf\xb5\xda",
    },
    {
        "chain": "BeerTokens",
        "policy": "Sha256Chain",
        "code3": "BER",
        "address_version": b"\xf2",
        "magic": b"\xf7\xbf\xb5\xdb",
    },
    {
        "chain": "SolidCoin",
        "policy": "Sha256Chain",
        "code3": "SCN",
        "address_version": b"\x7d",
        "magic": b"\xde\xad\xba\xbe",
    },
    {
        "chain": "ScTestnet",
        "policy": "Sha256Chain",
        "code3": "SC0",
        "address_version": b"\x6f",
        "magic": b"\xca\xfe\xba\xbe",
    },
    {
        "chain": "Worldcoin",
        "policy": "Sha256Chain",
        "code3": "WDC",
        "address_version": b"\x49",
        "magic": b"\xfb\xc0\xb6\xdb",
    },
    {"chain": "NovaCoin"},
    {"chain": "CryptoCash"},
    {
        "chain": "Anoncoin",
        "policy": "Sha256Chain",
        "code3": "ANC",
        "address_version": b"\x17",
        "magic": b"\xFA\xCA\xBA\xDA",
    },
    {"chain": "Hirocoin"},
    {"chain": "Maxcoin"},
    {"chain": "Dash"},
    {"chain": "BlackCoin"},
    {"chain": "Unbreakablecoin"},
    {"chain": "Californium"},
]


def create(name: str, src=None, **kwargs) -> BaseChain:
    """Instantiates the appropriate class for a chain with the name `name`

    Args:
        `name` (str): The name of the chain to be instantiated
        `src` (BaseChain): Allows passing in a chain to specify the object
        `kwargs` (PolicyAttrs): A dict of keyword arguments for configuration

    Returns:
        `Chain` (BaseChain): The instantiated class of the named chain
    """
    mod = __import__("Abe.chains", globals(), locals(), ["chains"], 0)

    if kwargs is None or not bool(kwargs):
        policy_kwargs: PolicyAttrs = next(
            item.copy() for item in CHAIN_CONFIG if item["chain"] == name
        )
        assert policy_kwargs["chain"] is not None
        name = policy_kwargs["name"] = policy_kwargs["chain"]
    else:
        # Ideally, the def would have **kwargs: Expand[PolicyAttrs] but this is not yet
        # available https://github.com/python/mypy/issues/4441
        # So, will leave the # type: ignore until it is.
        policy_kwargs = kwargs  # type: ignore

    policy_kwargs["chain"] = None

    if "policy" not in policy_kwargs:
        policy_kwargs["policy"] = name

    policy: str = policy_kwargs["policy"]
    chain = getattr(mod, policy)

    class Chain(chain):  # type: ignore
        """The fully configured chain"""

        def __init__(self, src=None, **kwargs):
            chain.__init__(self, src, **kwargs)

    return Chain(src, **policy_kwargs)
