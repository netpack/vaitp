class VulnerableSpotipy:
    def __init__(self):
        self.base_url = "https://api.spotify.com/v1"

    def track(self, track_id):
        # Directly using the track_id without validation
        url = f"{self.base_url}/tracks/{track_id}"
        return self.make_request(url)

    def make_request(self, url):
        # Placeholder for making the actual API request
        print(f"Making request to: {url}")
        # Here you would use requests or another library to make the API call

# Example usage
vulnerable_spotipy = VulnerableSpotipy()
# An attacker could exploit this by passing a malicious track_id
vulnerable_spotipy.track("../../playlists")  # This could redirect to an arbitrary endpoint