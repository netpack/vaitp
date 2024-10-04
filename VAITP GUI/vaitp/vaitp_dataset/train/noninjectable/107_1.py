# Import the copy module
import copy

# Define a malicious class that overrides the __reduce__ method
class Evil(object):
    def __reduce__(self):
        # Return a tuple of (function, arguments) to be executed
        return (eval, ("print('Hello, world!')",))

# Create an instance of the malicious class
evil = Evil()

# Copy the instance using the copy module
copy.copy(evil)