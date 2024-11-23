import re

class SafeLLMMathChain:
    def __init__(self, model):
        self.model = model

    def execute(self, prompt):
        # Sanitize the prompt to prevent code injection
        sanitized_prompt = self.sanitize_prompt(prompt)
        # Execute the model with the sanitized prompt
        return self.model.run(sanitized_prompt)

    def sanitize_prompt(self, prompt):
        # Remove any potentially dangerous code patterns
        safe_prompt = re.sub(r'[^a-zA-Z0-9\s\+\-\*/\(\)\.]+', '', prompt)
        return safe_prompt

# Example usage
model = SomeLLMModel()  # Replace with actual model
chain = SafeLLMMathChain(model)
result = chain.execute("2 + 2")  # Safe input