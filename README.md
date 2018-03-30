[![Build Status](https://travis-ci.org/Syndace/python-doubleratchet.svg?branch=master)](https://travis-ci.org/Syndace/python-doubleratchet)

# python-doubleratchet
#### A python implementation of the Double Ratchet algorithm.

This python library offers an implementation of the Double Ratchet algorithm as specified [here](https://signal.org/docs/specifications/doubleratchet/).

Goals of this implementation are:
- Keep it small and simple
- Don't assume any parameters, leave it all configurable
- Provide implementations of the recommended configurations for convenience
- Keep the structure close to the spec, so readers of the spec have an easy time understanding the code and structure

This library is currently in a very early state, most of the code has not been tested at all, there are probably bugs.

You can find examples in the [OMEMO library](https://github.com/Syndace/python-omemo), which uses this lib.
