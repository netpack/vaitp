# Example of using pdoc without the vulnerable option
# Ensure you are using pdoc 14.5.1 or later

import subprocess

# Generate documentation without linking to polyfill.io
subprocess.run(['pdoc', '--math', '--output-dir', 'docs', 'your_module_name'])