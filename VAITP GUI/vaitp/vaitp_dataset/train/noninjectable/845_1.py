# Example of vulnerable code demonstrating the CVE-2023-29522 vulnerability
# This code allows arbitrary execution of user-provided input, leading to potential remote code execution.

def execute_macro(user_input):
    # Directly executing user input as code without any validation or sanitization
    exec(user_input)

# Example usage
user_input = "import os; os.system('whoami')"  # Example of a dangerous payload
execute_macro(user_input)  # This would execute the command and print the output