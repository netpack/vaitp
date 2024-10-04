# bufferobject.c in Python 2.7.8 and later
# https://github.com/fedora-python/python26/blob/master/CVE-2014-7185.patch

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
    # Check for integer overflow
    if (offset > PY_SSIZE_T_MAX - size) {
        PyErr_SetString(PyExc_OverflowError,
                        "buffer size too large");
        return NULL;
    }
    if (offset > Py_SIZE(base)) {
        size = 0;
    }
    else {
        size = Py_SIZE(base) - offset;
    }
    # ...
    return PyBuffer_FromObject(base, offset, size);