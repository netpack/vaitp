# Vulnerable version of the package that could execute arbitrary code

def execute_arbitrary_code():
    # This simulates a potential code execution backdoor
    exec("print('This is a backdoor execution!')")

if __name__ == "__main__":
    execute_arbitrary_code()