import subprocess

def execute_command(user_input):
    # Whitelist of allowed commands
    allowed_commands = ['command1', 'command2', 'command3']  # Example allowed commands
    
    # Check if the user input is in the allowed commands
    if user_input in allowed_commands:
        # Use subprocess to execute the command safely
        subprocess.run([user_input])
    else:
        print("Invalid command.")

# Example usage
user_input = "cat /etc/passwd"  # Malicious input
execute_command(user_input)