import ast
import logging

def safe_script_invoke(script):
    # Use ast.literal_eval to safely evaluate expressions
    try:
        # Only allow safe expressions
        safe_code = ast.literal_eval(script)
        # Execute only if it's a safe expression
        return safe_code
    except (ValueError, SyntaxError) as e:
        logging.error(f"Invalid script: {e}")
        return None

# Example usage
user_input_script = "1 + 2"  # This should be a safe input
result = safe_script_invoke(user_input_script)
if result is not None:
    print(f"Result: {result}")
else:
    print("Execution failed due to unsafe script.")