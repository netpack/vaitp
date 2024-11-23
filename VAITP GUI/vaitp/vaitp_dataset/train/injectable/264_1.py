# Fixed version of the code to avoid code execution backdoor

def safe_function():
    print("This is a safe function.")

if __name__ == "__main__":
    safe_function()