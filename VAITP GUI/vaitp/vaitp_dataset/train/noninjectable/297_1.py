# Vulnerable code that imports the democritus-strings package
# which contains a potential code-execution backdoor.

import democritus_strings

# Example usage of the vulnerable package
def execute_vulnerable_function():
    democritus_strings.execute_malicious_code()

# Call the vulnerable function
execute_vulnerable_function()