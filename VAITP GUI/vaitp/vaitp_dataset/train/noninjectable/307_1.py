# Vulnerable version of the d8s-strings package with a potential backdoor

import subprocess

def execute_untrusted_code(code):
    # This function executes untrusted code, which is a security risk
    exec(code)

if __name__ == "__main__":
    # Example of potentially dangerous code that could be injected
    untrusted_code = "print('This code is executed!')"
    execute_untrusted_code(untrusted_code)