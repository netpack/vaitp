import ast
import traceback

class SafePythonCodeTool:
    def execute_code(self, code):
        # Use ast.literal_eval to safely evaluate expressions
        try:
            # Only allow safe expressions
            safe_code = ast.literal_eval(code)
            return safe_code
        except Exception as e:
            print(f"Error executing code: {traceback.format_exc()}")

# Example of usage
tool = SafePythonCodeTool()
result = tool.execute_code("[1, 2, 3]")  # Safe input
print(result)