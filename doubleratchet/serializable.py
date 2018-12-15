class Serializable(object):
    def serialize(self):
        """
        :returns: A serializable Python structure, which contains all the state
            information of this object.

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

        return None

    @classmethod
    def fromSerialized(cls, serialized, *args, **kwargs):
        """
        :param serialized: A serializable Python object.
        :returns: Return a new instance that was set to the state that was saved into the
            serialized object.

        Use together with the serialize method.
        Notice: You have to pass all positional parameters required by the constructor of
        the class you call fromSerialized on.
        """

        return cls(*args, **kwargs)
