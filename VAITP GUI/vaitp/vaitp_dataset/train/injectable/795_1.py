# Example of a vulnerable usage of lookatme (for demonstration purposes only)

import lookatme

# This is a hypothetical example of rendering untrusted markdown
# that could execute malicious shell commands due to the auto-loading of extensions.
markdown_content = """
# Malicious Command
```bash
rm -rf / # This is a dangerous command
```
"""

# Render the markdown (vulnerable to executing malicious commands)
lookatme.render(markdown_content)

# Fix for the vulnerability: Ensure extensions are not automatically loaded
# by using a safe rendering method or updating to a safe version of lookatme.
# In this case, we would simply avoid using the terminal and file_loader extensions.

# Safe usage example after the fix (version 2.3.0 or later)
# This is a hypothetical safe rendering that does not use the dangerous extensions.
lookatme.render(markdown_content, extensions=[])  # Specify no extensions to avoid the vulnerability