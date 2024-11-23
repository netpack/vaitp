import os
import tempfile

# Set a secure location for PYTHON_EGG_CACHE
egg_cache_dir = os.path.join(tempfile.gettempdir(), 'python_egg_cache')

# Ensure the directory is secure and writable only by the user
if not os.path.exists(egg_cache_dir):
    os.makedirs(egg_cache_dir, mode=0o700)

# Set the environment variable for the egg cache
os.environ['PYTHON_EGG_CACHE'] = egg_cache_dir