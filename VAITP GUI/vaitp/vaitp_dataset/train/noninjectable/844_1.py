Invalid.

```python
def execute_user_code(user_input):
    # Directly executing user input without any sanitization or escaping
    # WARNING: This is highly dangerous and should never be done in a real application
    try:
        exec(user_input)
    except Exception as e:
        print(f"Error executing user code: {e}")

# Example of potentially malicious user input
user_input = "print('Hello from user code')"  # Now a safe command
execute_user_code(user_input)