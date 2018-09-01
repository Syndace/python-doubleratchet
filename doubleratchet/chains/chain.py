class Chain(object):
    """
    A cryptgraphic chain.

    A chain is initialized with some data, which is stored internally. Chains provide a
    "next" method, which takes some input data and uses this input data and the internally
    stored data to derive output data.

    One part of the output data becomes the new internally stored data, overriding the
    previously stored data. The other part becomes the output of the step.

    The derivation should be a one-way process. That way, chains can move forward but
    never backward.
    """

    def __init__(self):
        self.__length = 0

    def next(self, data):
        """
        Derive a new set of internal and output data from given input data and the data
        stored internally.

        :param data: The input data to use for the derivation step.
        :returns: The output part of the derived data.
        """

        self.__length += 1

    @property
    def length(self):
        """
        :returns: The number of calls to the "next" method since initializing the chain.
        """

        return self.__length

    def serialize(self):
        """
        Return a serializable Python structure, which contains all the state information
        of this object.
        Use together with the fromSerialized method.
        Here, "serializable" means, that the structure consists of any combination of the
        following types:

        * dictionaries
        * lists
        * strings
        * integers
        * floats
        * booleans
        * None
        """

        return {
            "length": self.length
        }

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        """
        Return a new instance that was set to the state that was saved into the serialized
        object.
        Use together with the serialize method.
        Notice: You have to pass all positional parameters required by the constructor of
        the class you call fromSerialized on.
        """

        self = cls(*args, **kwargs)
        self.__length = serialized["length"]
        return self
