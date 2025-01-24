import builtins

from RestrictedPython._compat import IS_PY311_OR_GREATER


safe_builtins = {}

_safe_names = [
    '__build_class__',
    'None',
    'False',
    'True',
    'abs',
    'bool',
    'bytes',
    'callable',
    'chr',
    'complex',
    'divmod',
    'float',
    'hash',
    'hex',
    'id',
    'int',
    'isinstance',
    'issubclass',
    'len',
    'oct',
    'ord',
    'pow',
    'range',
    'repr',
    'round',
    'slice',
    'sorted',
    'str',
    'tuple',
    'zip'
]

_safe_exceptions = [
    'ArithmeticError',
    'AssertionError',
    'AttributeError',
    'BaseException',
    'BufferError',
    'BytesWarning',
    'DeprecationWarning',
    'EOFError',
    'EnvironmentError',
    'Exception',
    'FloatingPointError',
    'FutureWarning',
    'GeneratorExit',
    'IOError',
    'ImportError',
    'ImportWarning',
    'IndentationError',
    'IndexError',
    'KeyError',
    'KeyboardInterrupt',
    'LookupError',
    'MemoryError',
    'NameError',
    'NotImplementedError',
    'OSError',
    'OverflowError',
    'PendingDeprecationWarning',
    'ReferenceError',
    'RuntimeError',
    'RuntimeWarning',
    'StopIteration',
    'SyntaxError',
    'SyntaxWarning',
    'SystemError',
    'SystemExit',
    'TabError',
    'TypeError',
    'UnboundLocalError',
    'UnicodeDecodeError',
    'UnicodeEncodeError',
    'UnicodeError',
    'UnicodeTranslateError',
    'UnicodeWarning',
    'UserWarning',
    'ValueError',
    'Warning',
    'ZeroDivisionError',
]

if IS_PY311_OR_GREATER:
    _safe_exceptions.append("ExceptionGroup")

for name in _safe_names:
    safe_builtins[name] = getattr(builtins, name)

for name in _safe_exceptions:
    safe_builtins[name] = getattr(builtins, name)


def _write_wrapper():
    def _handler(secattr, error_msg):
        def handler(self, *args):
            try:
                f = getattr(self.ob, secattr)
            except AttributeError:
                raise TypeError(error_msg)
            return f(*args)

        return handler

    class Wrapper:
        def __init__(self, ob):
            self.__dict__['ob'] = ob

        __setitem__ = _handler(
            '__guarded_setitem__',
            'object does not support item or slice assignment')

        __delitem__ = _handler(
            '__guarded_delitem__',
            'object does not support item or slice assignment')

        __setattr__ = _handler(
            '__guarded_setattr__',
            'attribute-less object (assign or del)')

        __delattr__ = _handler(
            '__guarded_delattr__',
            'attribute-less object (assign or del)')
    return Wrapper


def _full_write_guard():
    safetypes = {dict, list, tuple, int, float, str, bool, bytes, type(None)}
    Wrapper = _write_wrapper()

    def guard(ob):
        if type(ob) in safetypes or hasattr(ob, '_guarded_writes'):
            return ob
        return Wrapper(ob)
    return guard


full_write_guard = _full_write_guard()


def guarded_setattr(object, name, value):
    setattr(full_write_guard(object), name, value)


safe_builtins['setattr'] = guarded_setattr


def guarded_delattr(object, name):
    delattr(full_write_guard(object), name)


safe_builtins['delattr'] = guarded_delattr


def safer_getattr(object, name, default=None, getattr=getattr):
    if name in ('format', 'format_map') and (
            isinstance(object, str) or
            (isinstance(object, type) and issubclass(object, str))):
        raise NotImplementedError(
            'Using the format*() methods of `str` is not safe')
    if name.startswith('_'):
        raise AttributeError(
            '"{name}" is an invalid attribute name because it '
            'starts with "_"'.format(name=name)
        )
    return getattr(object, name, default)


safe_builtins['_getattr_'] = safer_getattr


def guarded_iter_unpack_sequence(it, spec, _getiter_):
    for ob in _getiter_(it):
        yield guarded_unpack_sequence(ob, spec, _getiter_)


def guarded_unpack_sequence(it, spec, _getiter_):
    ret = list(_getiter_(it))

    if len(ret) < spec['min_len']:
        return ret

    for (idx, child_spec) in spec['childs']:
        ret[idx] = guarded_unpack_sequence(ret[idx], child_spec, _getiter_)

    return ret


safe_globals = {'__builtins__': safe_builtins}