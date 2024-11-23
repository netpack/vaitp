class SynapseHomeserver:
    def __init__(self):
        # Whitelist for trusted federation domains
        self.federation_domain_whitelist = {"trusted-server.com", "another-trusted-server.com"}

    def is_domain_trusted(self, domain):
        return domain in self.federation_domain_whitelist

    def get_well_known_file(self, domain):
        if not self.is_domain_trusted(domain):
            raise ValueError("Untrusted domain. Request denied.")
        
        # Logic to retrieve the .well-known file for trusted domains
        return f"Retrieved .well-known file from {domain}"

# Example usage
homeserver = SynapseHomeserver()

try:
    print(homeserver.get_well_known_file("malicious-server.com"))
except ValueError as e:
    print(e)  # Output: Untrusted domain. Request denied.