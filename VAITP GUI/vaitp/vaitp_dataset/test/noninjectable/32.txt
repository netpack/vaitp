def another_function(self, some, v1, v2, v3):
    if some is None:
        return v1 == v2
    no = object()
    return getattr(v1, some, no) == getattr(v3, some, no) is not no
