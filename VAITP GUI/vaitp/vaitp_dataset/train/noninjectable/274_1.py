# Vulnerable code that demonstrates the issue before the fix
import democritus_hypothesis  # This is the vulnerable package

def execute_malicious_code():
    democritus_hypothesis.run()  # Potentially harmful function

# Call the function that could execute malicious code
execute_malicious_code()