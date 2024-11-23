# Original vulnerable code using eval (not to be used)
# user_input = "some user input that could be malicious"
# result = eval(user_input)

# Fixed code using ast.literal_eval for safer evaluation
import ast

def safe_eval(user_input):
    try:
        # Only allow certain types of literals
        result = ast.literal_eval(user_input)
        return result
    except (ValueError, SyntaxError) as e:
        print("Invalid input:", e)
        return None

# Example usage
user_input = "{'key': 'value'}"  # Example of safe input
result = safe_eval(user_input)
print(result)