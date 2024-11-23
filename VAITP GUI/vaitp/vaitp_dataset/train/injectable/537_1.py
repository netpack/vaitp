import py_mini_racer

# Create a context for the JavaScript engine
context = py_mini_racer.MiniRacer()

# Safe execution of JavaScript code with proper input validation
def safe_execute(js_code):
    if isinstance(js_code, str) and len(js_code) < 1000:  # Example validation
        return context.eval(js_code)
    else:
        raise ValueError("Invalid JavaScript code")

# Example usage
try:
    result = safe_execute("2 + 2")
    print(result)  # Output: 4
except ValueError as e:
    print(e)