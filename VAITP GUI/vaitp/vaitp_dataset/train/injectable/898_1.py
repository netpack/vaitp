import re
from urllib.parse import urlparse

class SafeSpotipy:
    def __init__(self):
        self.base_url = "https://api.spotify.com/v1"

    def safe_track(self, track_id):
        # Validate the track_id to prevent directory traversal
        if not self.is_safe(track_id):
            raise ValueError("Invalid track ID")

        # Proceed with the API request if the track_id is safe
        url = f"{self.base_url}/tracks/{track_id}"
        return self.make_request(url)

    def is_safe(self, path):
        # Check for directory traversal patterns
        return not re.search(r'\.\.', path)

    def make_request(self, url):
        # Placeholder for making the actual API request
        print(f"Making request to: {url}")
        # Here you would use requests or another library to make the API call

# Example usage
spotipy = SafeSpotipy()
try:
    spotipy.safe_track("track_id_here")  # Replace with a valid track ID
except ValueError as e:
    print(e)