# Hypothetical example
class SharePointConnector:
    def __init__(self, user_permissions):
        self.user_permissions = user_permissions

    def get_documents(self):
        # Patched logic: checks for specific document access
        if "Limited Access" in self.user_permissions:
            return self.fetch_limited_access_documents()  # Now restricts access
        else:
            return self.fetch_all_documents()

    def fetch_all_documents(self):
        # Logic to fetch all documents from SharePoint
        return ["Document1", "Document2", "Document3"]

    def fetch_limited_access_documents(self):
        # Logic to fetch only documents the user has limited access to
        return ["LimitedDocument1", "LimitedDocument2"]