[![PyPI](https://img.shields.io/pypi/v/DoubleRatchet.svg)](https://pypi.org/project/DoubleRatchet/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/DoubleRatchet.svg)](https://pypi.org/project/DoubleRatchet/)
[![Build Status](https://travis-ci.org/Syndace/python-doubleratchet.svg?branch=master)](https://travis-ci.org/Syndace/python-doubleratchet)
[![Documentation Status](https://readthedocs.org/projects/python-doubleratchet/badge/?version=latest)](https://python-doubleratchet.readthedocs.io/en/latest/?badge=latest)

# python-doubleratchet #

A Python implementation of the [Double Ratchet algorithm](https://signal.org/docs/specifications/doubleratchet/).

## Installation ##

Install the latest release using pip (`pip install DoubleRatchet`) or manually from source by running `pip install .` (preferred) or `python setup.py install` in the cloned repository.

## Differences to the Specification ##

This library implements the core of the DoubleRatchet specification and includes a few of the recommended algorithms. This library does currently _not_ offer sophisticated decision mechanisms for the deletion of skipped message keys. Skipped message keys are only deleted when the maximum amount is reached and old keys are deleted from the storage in FIFO order. There is no time-based or event-based deletion.
