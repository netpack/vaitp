class SagemakerLLM:
    def complete(self, response):
        # Vulnerable code using eval
        result = eval(response)
        return result