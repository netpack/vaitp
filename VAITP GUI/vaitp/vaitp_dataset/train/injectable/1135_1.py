import re

class Vanna:
    def ask(self, prompt, visualize=True):
        if visualize:
            self.validate_prompt(prompt)
            # Proceed with intended visualization code
            print(f"Visualizing: {prompt}")
        else:
            # Handle non-visualization case
            print(f"Input received: {prompt}")

    def validate_prompt(self, prompt):
        # Simple validation to prevent code injection
        if re.search(r'[^a-zA-Z0-9\s]', prompt):
            raise ValueError("Invalid input detected!")

# Example usage
vanna = Vanna()
try:
    vanna.ask("Show me the results")  # Safe input
    vanna.ask("Show me the results; import os")  # Unsafe input, raises exception
except ValueError as e:
    print(e)