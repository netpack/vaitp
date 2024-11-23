# Fixed version of the d8s-strings package without the backdoor

def safe_function():
    # This function performs a safe operation without executing any untrusted code
    return "This is a safe operation."

if __name__ == "__main__":
    result = safe_function()
    print(result)