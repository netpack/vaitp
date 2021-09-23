from ._pystruct import Struct
try:
    from ._cstruct import _Struct as Struct  # noqa
except ImportError:  # pragma: no cover
    pass


__version__ = '3.1.0'  # pragma: no mutate
__all__ = ['Struct', 'FrozenStruct', 'merged', 'DefaultStruct', 'to_default_struct']  # pragma: no mutate


class Frozen(object):
    """
    Mixin to create an immutable class.
    """

    __slots__ = ()

    def __hash__(self):
        hash_key = '_hash'
        try:
            _hash = dict.__getattribute__(self, hash_key)
        except AttributeError:
            _hash = hash(tuple((k, self[k]) for k in sorted(self.keys())))
            dict.__setattr__(self, hash_key, _hash)
        return _hash

    def __setitem__(self, *_, **__):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__, ))

    def __setattr__(self, key, value):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__,))

    def setdefault(self, *_, **__):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__, ))

    def update(self, *_, **__):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__, ))

    def clear(self, *_, **__):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__, ))

    def __delitem__(self, *_, **__):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__, ))

    def __delattr__(self, *_, **__):
        raise TypeError("'%s' object attributes are read-only" % (type(self).__name__,))

    def __reduce__(self):
        return type(self), (), dict(self)

    def __setstate__(self, state):
        dict.update(self, state)

    def __copy__(self):
        return self


class FrozenStruct(Frozen, Struct):
    __slots__ = ('_hash', )


def merged(*dicts, **kwargs):
    """
    Merge dictionaries. Later keys overwrite.

    .. code-block:: python

        merged(dict(a=1), dict(b=2), c=3, d=1)

    """
    if not dicts:
        return Struct()
    result = dict()
    for d in dicts:
        result.update(d)
    result.update(kwargs)
    struct_type = type(dicts[0])
    return struct_type(**result)


class DefaultStruct(Struct):
    __slots__ = ('_default_factory',)

    def __init__(self, default_factory=None, *args, **kwargs):
        if default_factory is None:
            default_factory = DefaultStruct
        object.__setattr__(self, '_default_factory', default_factory)
        super(DefaultStruct, self).__init__(*args, **kwargs)

    def __missing__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError:
            default_factory = object.__getattribute__(self, '_default_factory')
            self[key] = new = default_factory()
            return new


def to_default_struct(d):
    if isinstance(d, DefaultStruct):
        return d
    elif isinstance(d, dict):
        return DefaultStruct(None, ((k, to_default_struct(v)) for k, v in d.items()))
    else:
        return d
