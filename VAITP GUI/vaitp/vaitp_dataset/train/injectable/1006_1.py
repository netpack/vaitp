# Assuming we have a simplified representation of a dynamic array in Vyper-like syntax

class DynamicArray:
    def __init__(self):
        self.data = []
    
    def append(self, value):
        self.data.append(value)
    
    def get(self, index):
        if index < 0 or index >= len(self.data):
            raise IndexError("Array index out of bounds")
        return self.data[index]
    
    def set(self, index, value):
        if index < 0 or index >= len(self.data):
            raise IndexError("Array index out of bounds")
        self.data[index] = value

# Example usage
array = DynamicArray()
array.append(1)
array.append(2)

# Correctly handling out-of-bounds access
try:
    array.set(2, 3)  # This should raise an error
except IndexError as e:
    print(e)  # Output: Array index out of bounds