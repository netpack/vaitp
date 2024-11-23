# Example of vulnerable code that could represent the CVE-2022-44051 vulnerability
# This code executes arbitrary code from an untrusted source

def execute_untrusted_code(code):
    exec(code)  # Dangerous: executes any code passed to it

# Example usage
untrusted_code = "print('This is a potential backdoor!')"
execute_untrusted_code(untrusted_code)