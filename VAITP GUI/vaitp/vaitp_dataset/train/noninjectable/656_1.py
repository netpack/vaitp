import os
import tempfile
from django.core.cache import FileBasedCache

class InsecureFileBasedCache(FileBasedCache):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_cache_directory()

    def _create_cache_directory(self):
        # Create the cache directory with the system's standard umask
        os.makedirs(self.location, exist_ok=True)

# Usage
cache = InsecureFileBasedCache('my_cache', location=tempfile.gettempdir())