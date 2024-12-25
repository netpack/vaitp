import math

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
        allowed_names = {"sqrt": math.sqrt}
        # Use eval with a limited scope to prevent arbitrary code execution
        try:
            return eval(expression, {"__builtins__": None}, allowed_names)
        except Exception as e:
            return f"Error during evaluation: {e}"

# Example usage
safe_chain = SafePALChain()
result = safe_chain.from_math_prompt("sqrt(16)")
print(result)
result2 = safe_chain.from_math_prompt("1+1")
print(result2)
result3 = safe_chain.from_math_prompt("os.system('ls')")
print(result3)