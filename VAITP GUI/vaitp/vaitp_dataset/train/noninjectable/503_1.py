# Vulnerable Python code example for CVE-2012-5659

import os
import sys

# Simulate the behavior of a vulnerable application
def vulnerable_function():
    # The application sets PYTHONPATH to an untrusted directory
    os.environ['PYTHONPATH'] = '/untrusted/directory'
    
    # The application then imports a module that should be from a trusted source
    # However, due to the modified PYTHONPATH, it could now import a malicious module
    try:
        import trusted_module
    except ImportError:
        print("Could not import the trusted module.")

# An attacker could place a malicious module in /untrusted/directory
# with the same name as a trusted module to execute arbitrary code.

# Example of running the vulnerable function
if __name__ == "__main__":
    vulnerable_function()