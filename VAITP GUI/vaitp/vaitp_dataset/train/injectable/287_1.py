# Fixed version of the code that avoids the use of the vulnerable package
# Instead of using the democritus-dicts package, we use a safe alternative

# Safe alternative implementation
class SafeDict:
    def __init__(self):
        self.data = {}

    def set_item(self, key, value):
        self.data[key] = value

    def get_item(self, key):
        return self.data.get(key, None)

# Example usage
safe_dict = SafeDict()
safe_dict.set_item('key1', 'value1')
print(safe_dict.get_item('key1'))  # Outputs: value1