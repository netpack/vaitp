import os
import spotipy
from spotipy.cache_handler import CacheHandler

class InsecureCacheHandler(CacheHandler):
    """
    A CacheHandler implementation that mimics the vulnerable behavior
    of Spotipy versions before 2.25.1 by creating cache files with
    insecure permissions (644).  This is for demonstration purposes only.
    Do NOT use this in production.
    """

    def __init__(self, cache_path=None):
        """
        Initializes the InsecureCacheHandler.

        Args:
            cache_path (str, optional): The path to the cache file.
                Defaults to '.spotipy_cache' in the current directory.
        """
        self.cache_path = cache_path or '.spotipy_cache'

    def get_cached_token(self):
        """
        Reads the access token from the cache file.

        Returns:
            dict: A dictionary containing the cached token information,
                  or None if the cache file does not exist or is empty.
        """
        try:
            with open(self.cache_path, 'r') as f:
                token_info = eval(f.read())  # DO NOT DO THIS IN PRODUCTION!
                return token_info
        except FileNotFoundError:
            return None
        except:
            return None

    def save_token_to_cache(self, token_info):
        """
        Saves the access token to the cache file with insecure permissions (644).

        Args:
            token_info (dict): A dictionary containing the token information.
        """
        try:
            with open(self.cache_path, 'w') as f:
                f.write(str(token_info))
            os.chmod(self.cache_path, 0o644)  # Insecure permissions
        except Exception as e:
            print(f"Error saving token to cache: {e}")

    def delete_cached_token(self):
        """
        Deletes the cache file.
        """
        try:
            os.remove(self.cache_path)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error deleting token cache: {e}")



if __name__ == '__main__':
    # WARNING: THIS CODE IS FOR DEMONSTRATION PURPOSES ONLY.
    # Using this code will create a file with insecure permissions.
    # Do NOT use this in a production environment.
    # Replace with your client_id, client_secret and redirect_uri
    client_id = 'YOUR_CLIENT_ID'
    client_secret = 'YOUR_CLIENT_SECRET'
    redirect_uri = 'YOUR_REDIRECT_URI'

    scope = 'user-read-email user-library-read playlist-modify-public'

    # Use the insecure cache handler
    cache_handler = InsecureCacheHandler(cache_path='.my_insecure_cache')

    sp = spotipy.Spotify(auth_manager=spotipy.SpotifyOAuth(client_id=client_id,
                                                           client_secret=client_secret,
                                                           redirect_uri=redirect_uri,
                                                           scope=scope,
                                                           cache_handler=cache_handler))

    # Example usage (this will trigger the token caching)
    try:
        user_profile = sp.me()
        print(f"Logged in as {user_profile['display_name']}")
    except Exception as e:
        print(f"Authentication failed: {e}")

    # After running this, check the permissions of the .my_insecure_cache file:
    # ls -l .my_insecure_cache
    # You should see -rw-r--r--