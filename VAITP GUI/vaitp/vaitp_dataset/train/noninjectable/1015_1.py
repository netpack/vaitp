from Products.CMFCore.PortalFolder import PortalFolder
import marshal

class VulnerablePortalFolder(PortalFolder):
    def load_data(self, data):
        # Vulnerable to arbitrary input leading to potential DoS
        return marshal.loads(data)