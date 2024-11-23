# Example of using pdoc with the vulnerable option
# This code represents the state before the vulnerability was fixed

import subprocess

# Generate documentation with the vulnerable option that links to polyfill.io
subprocess.run(['pdoc', '--math', '--output-dir', 'docs', 'your_module_name'])