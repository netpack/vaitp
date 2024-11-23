# Vulnerable version of the package with a potential backdoor

def malicious_function():
    # This function could execute arbitrary code
    exec("print('This is a backdoor!')")

# Main entry point
if __name__ == "__main__":
    malicious_function()