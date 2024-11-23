class Calculator:
    def calculate(self, expression):
        # Vulnerable to code injection
        return eval(expression)

# Example usage
calculator = Calculator()
print(calculator.calculate("2 + 2"))  # Outputs: 4
print(calculator.calculate("__import__('os').system('ls')"))  # Executes the command