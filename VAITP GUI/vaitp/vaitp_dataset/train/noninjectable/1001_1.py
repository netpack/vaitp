class PythonAstREPLTool:
    def _run(self, code):
        # Vulnerable code: directly evaluating arbitrary code
        try:
            result = eval(code)  # Unsafe evaluation of code
            return result
        except Exception as e:
            return f"Error: {str(e)}"

# Example usage
tool = PythonAstREPLTool()
result = tool._run("__import__('os').system('ls')")  # Arbitrary code execution
print(result)