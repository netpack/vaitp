# Example of a patch to restrict execution of arbitrary script macros in XWiki

def execute_macro(user, macro_code):
    # Check if the user has permission to execute macros
    if not user.has_permission("execute_macro"):
        raise PermissionError("User  does not have permission to execute macros.")

    # Validate and sanitize the macro code to prevent arbitrary execution
    allowed_macros = ["safe_macro1", "safe_macro2"]  # Define allowed macros
    if macro_code not in allowed_macros:
        raise ValueError("Macro execution is restricted.")

    # Execute the safe macro
    return run_safe_macro(macro_code)

def run_safe_macro(macro_code):
    # Implementation of safe macros
    if macro_code == "safe_macro1":
        return "Executing safe macro 1"
    elif macro_code == "safe_macro2":
        return "Executing safe macro 2"

# Example usage
try:
    user = get_current_user()  # Function to get the current user
    result = execute_macro(user, "some_dangerous_macro")
    print(result)
except (PermissionError, ValueError) as e:
    print(f"Error: {e}")