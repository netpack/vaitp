class SynapseHomeserver:
    def get_well_known_file(self, domain):
        # No validation of the domain, allowing any domain to be queried
        # This can lead to a denial of service if the domain is malicious
        response = self.fetch_well_known_file(domain)
        return response

    def fetch_well_known_file(self, domain):
        # Simulated fetch of the .well-known file, which could be a large file
        # For demonstration purposes, we will just return a string
        return f"Retrieved .well-known file from {domain}"

# Example usage
homeserver = SynapseHomeserver()

# This could be a malicious server that redirects to a large file
print(homeserver.get_well_known_file("malicious-server.com"))