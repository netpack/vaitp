import re

def check_for_invalid_imports(template_code):
    # Block any import statements that are not preceded by a comment
    # This regex matches lines that start with "#from" or "#import"
    if re.search(r'^\s*#(from|import)\s+', template_code, re.MULTILINE):
        raise ValueError("Import statements are not allowed in templates.")
    
    # Additional logic to process the template code safely
    # ...

# Example usage
try:
    check_for_invalid_imports("""
    # This is a comment
    #from os import path  # This should raise an error
    print("Hello, World!")
    """)
except ValueError as e:
    print(e)