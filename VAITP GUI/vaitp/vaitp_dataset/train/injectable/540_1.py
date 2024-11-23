class SafePALChain:
    def __init__(self, allowed_functions=None):
        self.allowed_functions = allowed_functions or {}

    def execute(self, code):
        # Use a restricted execution environment
        exec_globals = {"__builtins__": {}}
        exec_globals.update(self.allowed_functions)

        try:
            exec(code, exec_globals)
        except Exception as e:
            print(f"Execution failed: {e}")

# Example of how to use the SafePALChain
allowed_funcs = {
    'print': print,
    # Add other safe functions as needed
}

safe_chain = SafePALChain(allowed_functions=allowed_funcs)
safe_chain.execute("print('Hello, World!')")  # Safe execution
safe_chain.execute("__import__('os').system('ls')")  # This will fail