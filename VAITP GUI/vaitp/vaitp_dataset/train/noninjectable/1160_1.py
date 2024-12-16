import eval

def process_expression(project_id, expression):
    # Vulnerable code: Directly evaluating user-supplied expression
    try:
        result = eval(expression)  # THIS IS THE VULNERABLE LINE
        return result
    except Exception as e:
        return f"Error: {e}"


user_expression = input("Enter an expression: ") #Potentially malicious input from a crafted URL
project_id = "some_valid_project_id" # Obtained somehow by the attacker

result = process_expression(project_id, user_expression)
print(result)
