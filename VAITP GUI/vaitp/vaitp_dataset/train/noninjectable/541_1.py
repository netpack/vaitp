class LLMMathChain:
    def __init__(self, model):
        self.model = model

    def execute(self, prompt):
        # Using eval() instead of exec() for evaluating math expressions
        try:
          result = eval(prompt)
          print(result)
        except Exception as e:
          print(f"Error evaluating expression: {e}")

# Example usage
class SomeLLMModel: #Dummy class for the example
    pass
model = SomeLLMModel()  # Replace with actual model
chain = LLMMathChain(model)
chain.execute("2 + 2")  # Safe arithmetic input