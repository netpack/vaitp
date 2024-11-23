class PALChain:
    def __init__(self):
        pass

    def from_math_prompt(self, prompt):
        # Vulnerable code using exec
        exec(f"result = {prompt}")
        return result

    def from_colored_object_prompt(self, prompt):
        # Vulnerable code using exec
        exec(f"result = {prompt}")
        return result

# Example usage
chain = PALChain()
# An attacker could input a malicious prompt
result = chain.from_math_prompt("os.system('echo Vulnerable')")
print(result)  # This could execute arbitrary code