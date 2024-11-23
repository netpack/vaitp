class VulnerableExecutor:
    def execute_code(self, code):
        # Vulnerable to arbitrary code execution
        exec(code)

# Example usage
executor = VulnerableExecutor()

# This code can be executed, potentially allowing for arbitrary code execution
user_input = "__import__('os').system('echo Vulnerable!')"
executor.execute_code(user_input)