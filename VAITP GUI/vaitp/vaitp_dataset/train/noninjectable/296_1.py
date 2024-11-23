# Vulnerable code that demonstrates the potential code-execution backdoor

# Importing the vulnerable democritus-file-system package
from democritus_file_system import unsafe_function

# Calling the unsafe function that could execute arbitrary code
unsafe_function()