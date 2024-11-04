# Hypothetical example
class SharePointConnector:
    def __init__(self, user_permissions):
        self.user_permissions = user_permissions

    def get_documents(self):
        # Vulnerable logic: does not check for full access
        if "Limited Access" in self.user_permissions:
            return self.fetch_all_documents()  # Flaw: grants access to all documents
        else:
            return self.fetch_restricted_documents()

    def fetch_all_documents(self):
        # Logic to fetch all documents from SharePoint
        return ["Document1", "Document2", "Document3"]

    def fetch_restricted_documents(self):
        # Logic to fetch only restricted documents
        return ["RestrictedDocument1"]