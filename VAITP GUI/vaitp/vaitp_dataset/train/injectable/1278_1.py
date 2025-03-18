import os
import stat

def create_cache_file(filename, content):
    """
    Creates a cache file with tightened permissions.
    """
    try:
        with open(filename, 'w') as f:
            f.write(content)

        # Set file permissions to rw------- (600)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    except OSError as e:
        print(f"Error creating or modifying cache file: {e}")

if __name__ == '__main__':
    cache_filename = 'my_spotify_cache.txt'
    auth_token = 'sensitive_spotify_auth_token'  # Replace with actual token

    create_cache_file(cache_filename, auth_token)
    print(f"Cache file '{cache_filename}' created with secure permissions.")