import os

def execute_command(name):
    # Unsanitized input passed directly to os.system
    command = f"echo {name}"  # Example command
    os.system(command)

# Example usage
user_input = "user_input; ls"  # Replace with actual user input
execute_command(user_input)