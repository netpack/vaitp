class PythonCodeTool:
    def execute_code(self, code):
        # Directly using eval to execute arbitrary code
        try:
            exec(code)
        except Exception as e:
            print(f"Error executing code: {e}")

# Example of usage
tool = PythonCodeTool()
tool.execute_code("import os; os.system('ls')")  # Dangerous code execution