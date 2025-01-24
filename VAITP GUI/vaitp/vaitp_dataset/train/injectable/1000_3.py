# Test select.poll in combination with file descriptors.

try:
    import select, errno
    import os

    select.poll  # Raises AttributeError for CPython implementations without poll()
except (ImportError, AttributeError):
    print("SKIP")
    raise SystemExit

# Check that poll supports registering file descriptors (integers).
try:
    poller = select.poll()
    if hasattr(os, 'supports_fd') and not os.supports_fd(0):
        print("SKIP")
        raise SystemExit
    poller.register(0)
except OSError:
    print("SKIP")
    raise SystemExit

# Register invalid file descriptor.
try:
    poller = select.poll()
    poller.register(-1)
except ValueError:
    print("ValueError")

# Test polling stdout, it should be writable.
poller = select.poll()
poller.register(1, select.POLLOUT)
print(poller.poll())

# Unregister then re-register.
poller.unregister(1)
poller.register(1, select.POLLIN)

# Poll for input, should return an empty list.
print(poller.poll(0))

# Test registering a very large number of file descriptors (will trigger
# EINVAL due to more than OPEN_MAX fds).
poller = select.poll()
max_fd = os.sysconf('SC_OPEN_MAX') if hasattr(os, 'sysconf') else 256  # Fallback
for fd in range(min(6000,max_fd)):
    poller.register(fd)
try:
    poller.poll()
    assert False
except OSError as er:
    print(er.errno == errno.EINVAL)

# Register stdout/stderr, plus many extra ones to trigger the fd vector
# resizing. Then unregister the excess ones and verify poll still works.
poller = select.poll()
max_fd = os.sysconf('SC_OPEN_MAX') if hasattr(os, 'sysconf') else 256  # Fallback
for fd in range(1, min(1000, max_fd)):
    poller.register(fd)
for i in range(3, min(1000, max_fd)):
    poller.unregister(i)
print(sorted(poller.poll()))
