class SafePALChain:
    def __init__(self):
        pass

    def from_math_prompt(self, prompt):
        # Instead of using exec, use a safe evaluation method
        return self.safe_eval(prompt)

    def from_colored_object_prompt(self, prompt):
        # Instead of using exec, use a safe evaluation method
        return self.safe_eval(prompt)

    def safe_eval(self, expression):
        # Use a restricted environment for evaluation
        allowed_names = {"sqrt": __import__('math').sqrt}
        # Use eval with a limited scope to prevent arbitrary code execution
        return eval(expression, {"__builtins__": None}, allowed_names)

# Example usage
safe_chain = SafePALChain()
result = safe_chain.from_math_prompt("sqrt(16)")
print(result)  # Outputs: 4.0