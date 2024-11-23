class LLMMathChain:
    def __init__(self, model):
        self.model = model

    def execute(self, prompt):
        # Directly execute the prompt using exec, which can be dangerous
        exec(prompt)

# Example usage
model = SomeLLMModel()  # Replace with actual model
chain = LLMMathChain(model)
chain.execute("print('This is an arbitrary code execution!')")  # Vulnerable input