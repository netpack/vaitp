import os

# Using a potentially insecure location for PYTHON_EGG_CACHE
egg_cache_dir = '/tmp/python_egg_cache'

# Create the directory without secure permissions
if not os.path.exists(egg_cache_dir):
    os.makedirs(egg_cache_dir)

# Set the environment variable for the egg cache
os.environ['PYTHON_EGG_CACHE'] = egg_cache_dir