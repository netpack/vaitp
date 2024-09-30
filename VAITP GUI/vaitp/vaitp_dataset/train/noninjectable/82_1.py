import typed_ast.ast3 as ast

def parse_python_code(code):
    return ast.parse(code)

# Vulnerable code: parsing malicious Python code
malicious_code = "a" * (10**6)  # Create a large string of 'a's
try:
    parse_python_code(malicious_code)
except Exception as e:
    print(f"Error parsing code: {e}")