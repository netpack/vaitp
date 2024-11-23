def vulnerable_select_where(query):
    # Vulnerable implementation that uses eval
    result = eval(query)  # This is unsafe and allows arbitrary code execution
    return result

# Example of a crafted query that could exploit the vulnerability
user_input = "os.system('echo Vulnerable!')"
vulnerable_select_where(user_input)