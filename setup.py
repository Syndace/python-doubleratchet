#!/usr/bin/env python

from distutils.core import setup

setup(
    name = "DoubleRatchet",
    version = "0.1",
    description = "A python implementation of the Double Ratchet algorithm.",
    author = "Tim Henkes",
    url = "https://github.com/Syndace/python-doubleratchet",
    packages = ["doubleratchet", "doubleratchet.chains", "doubleratchet.exceptions", "doubleratchet.ratchets", "doubleratchet.recommended"],
    requires = ["scci", "hkdf"],
    provides = ["doubleratchet"]
)
