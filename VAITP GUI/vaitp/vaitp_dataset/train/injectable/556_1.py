class SafeExecutor:
    def __init__(self, allowed_globals=None):
        self.allowed_globals = allowed_globals or {}

    def safe_exec(self, code, local_vars=None):
        # Only allow a restricted set of globals
        exec(code, self.allowed_globals, local_vars)

# Example usage
safe_globals = {
    "__builtins__": {
        "print": print,  # Only allow print function
        # Add other safe built-ins as needed
    }
}

executor = SafeExecutor(allowed_globals=safe_globals)

# This code can be executed safely
safe_code = "print('Hello, safe world!')"
executor.safe_exec(safe_code)