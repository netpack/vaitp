import py_mini_racer

# Create a context for the JavaScript engine
context = py_mini_racer.MiniRacer()

# Unsafe execution of JavaScript code without input validation
def unsafe_execute(js_code):
    return context.eval(js_code)

# Example usage with potentially unsafe input
user_input = "console.log('Hello, World!');" + "A" * 10000  # Simulating large input
result = unsafe_execute(user_input)
print(result)