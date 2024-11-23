class VulnerableReferenceTable:
    def __init__(self):
        self.references = {}

    def add_reference(self, name, url):
        # Allows duplicate entries, leading to collisions
        if name in self.references:
            self.references[name].append(url)
        else:
            self.references[name] = [url]

    def get_reference(self, name):
        # Poor hash function can lead to long retrieval times
        return self.references.get(name, None)

# Example usage demonstrating vulnerability
vulnerable_table = VulnerableReferenceTable()
for i in range(1000):
    # This simulates generating many collisions
    vulnerable_table.add_reference("collision_key", f"https://www.example.com/{i}")
print(vulnerable_table.get_reference("collision_key"))