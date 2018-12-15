from __future__ import absolute_import

from ..serializable import Serializable

class Ratchet(Serializable):
    """
    A cryptographic ratchet.

    A ratchet manages some sort of internal state and offers a "step" method, which uses
    the current state and optional additional data to derive the next state. The new state
    overrides the old state. The derivation must be a one-way process, so that the ratchet
    can't go back to a previous state.
    """

    def step(self, *args, **kwargs):
        """
        Perform a ratchet step using provided arguments.
        """

        raise NotImplementedError
