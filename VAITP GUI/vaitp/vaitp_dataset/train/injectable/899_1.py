class SafeReferenceTable:
    def __init__(self):
        self.references = {}

    def add_reference(self, name, url):
        if name in self.references:
            raise ValueError("Duplicate reference names are not allowed.")
        self.references[name] = url

    def get_reference(self, name):
        return self.references.get(name, None)

# Example usage
reference_table = SafeReferenceTable()
reference_table.add_reference("example", "https://www.example.com")
print(reference_table.get_reference("example"))