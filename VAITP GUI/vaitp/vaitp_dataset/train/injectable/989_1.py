import pandas as pd
from pandasai import PandasAI

# Securely restrict execution of arbitrary code
class SafeSDFCodeExecutor:
    def execute(self, code):
        # Implement a safe execution context or restrict allowed operations
        # For example, you could use a restricted environment or a sandbox
        raise NotImplementedError("Execution of arbitrary code is disabled.")

# Use the safe executor in the PandasAI context
pandas_ai = PandasAI(executor=SafeSDFCodeExecutor())

# Example usage
data = {
    "input": ["Generate a DataFrame with two columns: name and age."],
}
df = pd.DataFrame(data)

# This will not execute arbitrary code
result = pandas_ai(df)
print(result)