# Fixed version of the code that no longer imports the vulnerable package

# Instead of using the democritus-dicts package, we will use a safe alternative
# or simply avoid using any untrusted package.

# Safe alternative implementation
class SafeDict:
    def __init__(self):
        self.data = {}

    def set_item(self, key, value):
        self.data[key] = value

    def get_item(self, key):
        return self.data.get(key, None)

# Example usage of the SafeDict class
safe_dict = SafeDict()
safe_dict.set_item('key1', 'value1')
print(safe_dict.get_item('key1'))  # Output: value1