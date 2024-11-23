import json

class SagemakerLLM:
    def complete(self, response):
        # Vulnerable code using eval (not recommended)
        # result = eval(response)

        # Fixed code using json.loads to safely parse the response
        try:
            result = json.loads(response)
        except json.JSONDecodeError as e:
            raise ValueError("Invalid JSON response") from e

        return result