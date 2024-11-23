class VulnerableDynamicArray:
    def __init__(self):
        self.data = []
    
    def append(self, value):
        self.data.append(value)
    
    def get(self, index):
        return self.data[index]  # Vulnerable to out-of-bounds access
    
    def set(self, index, value):
        # Vulnerability: does not check for out-of-bounds access
        self.data[index] = value

# Example usage demonstrating the vulnerability
array = VulnerableDynamicArray()
array.append(1)
array.append(2)

# This will cause an out-of-bounds access
array.set(2, 3)  # No error handling, may lead to data corruption
print(array.get(2))  # This could lead to unexpected behavior or corruption