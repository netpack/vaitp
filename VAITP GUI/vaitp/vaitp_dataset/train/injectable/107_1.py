# Import the copy module
import copy

# Define a safe class that does not override the __reduce__ method
class Safe(object):
    def __init__(self, data):
        self.data = data

# Create an instance of the safe class
safe = Safe('Hello, world!')

# Copy the instance using the copy module
copy.copy(safe)