Getting Started
===============

This quick start guide assumes knowledge of the `Double Ratchet algorithm <https://signal.org/docs/specifications/doubleratchet/>`_.

Next to a few container classes and interfaces, the four major units of this library are :class:`~doubleratchet.double_ratchet.DoubleRatchet`, :class:`~doubleratchet.diffie_hellman_ratchet.DiffieHellmanRatchet`, :class:`~doubleratchet.symmetric_key_ratchet.SymmetricKeyRatchet` and :class:`~doubleratchet.kdf_chain.KDFChain`. These classes are structured roughly the same:

* Instances can be created through factory methods (called e.g. ``create``), **NOT** by calling the constructor/``__init__``.
* Instances can be serialized into JSON-friendly data structures.
* When creating a new instance or deserializing an old instance, a set of configuration options has to be passed. Note that it is your responsibility to pass the same configuration when deserializing as you passed when creating the instance.
* Some of the classes are abstract, requiring you to subclass them and to implement one or two abstract methods.
* For some of the interfaces and abstract classes, implementations using recommended cryptographic primitives are available in the :doc:`doubleratchet.recommended <doubleratchet/recommended/package>` package.

The :class:`~doubleratchet.double_ratchet.DoubleRatchet` class offers a thin and simple message en-/decryption API, using and combining all of the other classes under the hood. For details on the configuration, refer to the :meth:`~doubleratchet.double_ratchet.DoubleRatchet.encrypt_initial_message` or :meth:`~doubleratchet.double_ratchet.DoubleRatchet.decrypt_initial_message` methods of the :class:`~doubleratchet.double_ratchet.DoubleRatchet` class. Take a look at the `Double Ratchet Chat example <https://github.com/Syndace/python-doubleratchet/tree/master/examples/dr_chat.py>`_ in the python-doubleratchet repository for an example of a full configuration, including the required subclassing and using some of the recommended implementations.

This library implements the core of the DoubleRatchet specification and includes a few of the recommended algorithms. This library does currently *not* offer sophisticated decision mechanisms for the deletion of skipped message keys. Skipped message keys are only deleted when the maximum amount is reached and old keys are deleted from the storage in FIFO order. There is no time-based or event-based deletion.
