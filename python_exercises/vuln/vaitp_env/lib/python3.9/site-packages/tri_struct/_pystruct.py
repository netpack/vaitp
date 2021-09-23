class Struct(dict):
    """
    Struct is a dict that can be accessed like an object. It also has a predictable repr so it can be used in tests for example.

    .. code-block:: python

        >>> bs = Struct(a=1, b=2, c=3)
        >>> bs
        Struct(a=1, b=2, c=3)
        >>> bs.a
        1

    * Struct(**kwargs) -> new Struct initialized with the name=value pairs in the keyword aasdrgument list. For example: Struct(one=1, two=2)
    * Struct() -> new empty Struct
    * Struct(mapping) -> new Struct initialized from a mapping object's (key, value) pairs
    * Struct(iterable) -> new Struct initialized as if via:
        .. code-block:: python

            s = Struct()
            for k, v in iterable:
                s[k] = v

    """
    __slots__ = ()

    def __repr__(self):
        pieces = (
            "%s=%s" % (key,
                       (repr(val) if val is not self
                        else "%s(...)" % type(self).__name__)
                       )
            for (key, val) in sorted(self.items())
        )
        return "%s(%s)" % (type(self).__name__,
                           ", ".join(pieces))

    __str__ = __repr__

    def __getattribute__(self, item):
        if item not in self:
            try:
                return object.__getattribute__(self, item)
            except AttributeError as e:
                try:
                    missing_ = object.__getattribute__(self, '__missing__')
                    return missing_.__get__(self)(item)
                except AttributeError:
                    raise e
        return self[item]

    def __setattr__(self, key, value):
        self[key] = value

    def __delattr__(self, item):
        try:
            del self[item]
        except KeyError:
            object.__delattr__(self, item)

    def copy(self):
        return type(self)(self)


Struct.__module__ = "tri_struct"
