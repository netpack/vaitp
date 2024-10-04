# bufferobject.c in Python before 2.7.8
# https://github.com/python/cpython/blob/2.7/Objects/bufferobject.c

def buffer(object, offset=0, size=None):
    # ...
    if (offset < 0) {
        PyErr_SetString(PyExc_ValueError,
                        "offset must be zero or positive");
        return NULL;
    }
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError,
                        "size must be zero or positive");
        return NULL;
    }
    # ...
    if (offset > Py_SIZE(base)) {
        size = 0;
    }
    else {
        size = Py_SIZE(base) - offset;
    }
    # ...
    return PyBuffer_FromObject(base, offset, size);