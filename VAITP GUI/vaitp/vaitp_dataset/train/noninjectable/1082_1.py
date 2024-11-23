# Example of vulnerable code that uses eval on database values

def retrieve_value_from_database(db_value):
    # Directly using eval on the database value, leading to arbitrary code execution
    return eval(db_value)

# Example usage
user_input = "__import__('os').system('ls')"  # Simulated malicious input
result = retrieve_value_from_database(user_input)
print(result)  # This will execute the command and list directory contents