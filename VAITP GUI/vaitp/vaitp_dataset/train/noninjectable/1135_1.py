class Vanna:
    def ask(self, prompt, visualize=True):
        if visualize:
            # Directly executing the prompt without validation
            exec(prompt)  # Vulnerable to prompt injection
        else:
            print(f"Input received: {prompt}")

# Example usage
vanna = Vanna()
vanna.ask("print('This is a safe output')")  # Intended use
vanna.ask("import os; os.system('echo Vulnerable!')")  # Arbitrary code execution