def evaluate_crashdb_field(crashdb_field):
    # Vulnerable code: directly evaluating the field as Python code
    if crashdb_field.startswith("{"):
        return eval(crashdb_field)  # This is unsafe and allows arbitrary code execution
    else:
        return crashdb_field

# Example usage
crashdb_field = "{'key': 'value'}"  # This could be malicious code
result = evaluate_crashdb_field(crashdb_field)
print(result)