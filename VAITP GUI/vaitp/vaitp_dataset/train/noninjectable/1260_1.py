import os
import json
import stat

class CredentialCache:
    def __init__(self, cache_dir="/tmp/.snowflake_cache"):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    def cache_credentials(self, username, token):
        cache_file = os.path.join(self.cache_dir, f"{username}_creds.json")
        credentials = {"token": token}
        with open(cache_file, "w") as f:
            json.dump(credentials, f)
        os.chmod(cache_file, 0o644)  # World-readable permissions

    def get_cached_credentials(self, username):
         cache_file = os.path.join(self.cache_dir, f"{username}_creds.json")
         if os.path.exists(cache_file):
             with open(cache_file, "r") as f:
                credentials = json.load(f)
                return credentials.get("token")
         return None

if __name__ == '__main__':
    cache = CredentialCache()
    username = "testuser"
    token = "test_secret_token"
    cache.cache_credentials(username, token)
    retrieved_token = cache.get_cached_credentials(username)
    print(f"Retrieved token: {retrieved_token}")


    # Simulate an attacker reading the world-readable file
    import subprocess
    cache_file = os.path.join(cache.cache_dir, f"{username}_creds.json")
    try:
      # Note that the vulnerable code did not explicitly expose the location for others to execute,
      # it would require that an attacker would need to have knowledge of it.
      result = subprocess.run(['cat', cache_file], capture_output=True, text=True, check=True)
      print(f"Attacker read cache file content: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
      print(f"Error reading cache file: {e}")