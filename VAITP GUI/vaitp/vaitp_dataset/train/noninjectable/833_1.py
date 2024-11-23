# Example of vulnerable code allowing execution of arbitrary script macros

def execute_macro(user, macro_code):
    # No permission check, any user can execute macros
    # Directly executing the macro code without validation
    exec(macro_code)

# Example usage
user = get_current_user()  # Function to get the current user
macro_input = "import os; os.system('echo Vulnerable!')"  # Arbitrary macro input
execute_macro(user, macro_input)  # This would execute the macro