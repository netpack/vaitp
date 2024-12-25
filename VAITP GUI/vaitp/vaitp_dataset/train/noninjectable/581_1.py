import os

def execute_command(command):
    # Dynamically evaluate the command without validation
    # Using eval is dangerous, consider using subprocess instead
    try:
      return eval(command, {'os': os})
    except Exception as e:
      return f"Error executing command: {e}"

# Example usage
user_input = "os.system('ls')"  # Arbitrary command input
print(execute_command(user_input))