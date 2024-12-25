Invalid
```python
def execute_arbitrary_script(script):
    # This function allows arbitrary execution of Python commands
    # It's extremely dangerous and should NOT be used in a real application
    # exec(script) # This line is the problem, it's commented out for safety
    print("Arbitrary script execution is disabled for safety reasons")

# Example of a potentially malicious script that could be executed
malicious_script = "import os; os.system('rm -rf /')"  # Dangerous command

# Simulating a script event handler that could trigger the execution
def on_mouse_over():
    execute_arbitrary_script(malicious_script)

# Trigger the event
on_mouse_over()