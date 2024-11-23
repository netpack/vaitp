# Example of vulnerable code before the fix for CVE-2023-50423

from sap_xssec import SecurityContext

class VulnerableSecurityContext(SecurityContext):
    def __init__(self, token):
        super().__init__(token)
        # No token validation is performed, leading to potential privilege escalation

# Usage
vulnerable_context = VulnerableSecurityContext("user_provided_token")
# Proceed with operations without any validation