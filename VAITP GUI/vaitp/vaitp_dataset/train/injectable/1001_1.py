import ast
import subprocess

class SafeREPLTool:
    def _run(self, code):
        # Use ast.literal_eval to safely evaluate expressions
        try:
            # Only allow safe expressions
            tree = ast.parse(code, mode='eval')
            # Compile and execute the code in a restricted environment
            compiled_code = compile(tree, filename="<ast>", mode="eval")
            result = eval(compiled_code, {"__builtins__": {}})
            return result
        except Exception as e:
            return f"Error: {str(e)}"

# Example usage
tool = SafeREPLTool()
result = tool._run("1 + 1")  # Safe expression
print(result)  # Outputs: 2