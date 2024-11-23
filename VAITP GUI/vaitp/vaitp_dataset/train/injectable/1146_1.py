import ast

class SafeCalculator:
    def calculate(self, expression):
        # Use ast.literal_eval to safely evaluate expressions
        try:
            result = ast.literal_eval(expression)
            return result
        except (ValueError, SyntaxError):
            return "Invalid expression"

# Example usage
calculator = SafeCalculator()
print(calculator.calculate("2 + 2"))  # Outputs: 4
print(calculator.calculate("__import__('os').system('ls')"))  # Outputs: Invalid expression