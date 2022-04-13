.. _serialization_and_migration:

Serialization and Migration
===========================

python-doubleratchet uses `pydantic <https://pydantic-docs.helpmanual.io/>`_ for serialization internally. All classes that support serialization offer a property called ``model`` which returns the internal state of the instance as a pydantic model, and a method called ``from_model`` to restore the instance from said model. However, while these properties/methods are available for public access, migrations can't automatically be performed when working with models directly. Instead, the property ``json`` is provided, which returns the internal state of the instance a JSON-friendly Python dictionary, and the method ``from_json``, which restores the instance *after* performing required migrations on the data. Unless you have a good reason to work with the models directly, stick to the JSON serialization APIs.

Migration from pre-stable
-------------------------

Migration from pre-stable is provided, however, since the class hierarchy and serialization concept has changed, only whole Double Ratchet objects can be migrated to stable. Use the ``from_json`` method as usual.
