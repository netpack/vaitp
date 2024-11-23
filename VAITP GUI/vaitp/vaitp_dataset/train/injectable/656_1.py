import os
import tempfile
from django.core.cache import FileBasedCache

class SecureFileBasedCache(FileBasedCache):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._set_secure_permissions()

    def _set_secure_permissions(self):
        # Set the umask to 0o077 to ensure that the intermediate directories
        # have restrictive permissions
        original_umask = os.umask(0o077)
        try:
            # Create the cache directory with secure permissions
            os.makedirs(self.location, exist_ok=True)
        finally:
            os.umask(original_umask)

# Usage
cache = SecureFileBasedCache('my_cache', location=tempfile.gettempdir())