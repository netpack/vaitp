# Example of a vulnerable usage of lookatme (for demonstration purposes only)

import lookatme

# This is a hypothetical example of untrusted markdown content
markdown_content = """
# Example of Malicious Command
```bash
echo 'This could execute a command!'
```
"""

# Render the markdown (vulnerable to executing malicious commands)
# Prior to version 2.3.0, this would automatically load dangerous extensions
lookatme.render(markdown_content)

# The above code could potentially execute harmful shell commands
# if untrusted markdown is rendered, due to the auto-loading of extensions.