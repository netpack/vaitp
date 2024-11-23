# Example code demonstrating the vulnerability before it was fixed

def import_attachment(attachment_content):
    """
    Imports attachment content without proper escaping, leading to potential code execution.
    """
    # Directly using user input without escaping
    execute_code(attachment_content)

def execute_code(code):
    """
    Executes arbitrary code, which can lead to severe security vulnerabilities.
    This simulates the execution of Groovy, Python, or Velocity code.
    """
    exec(code)  # Dangerous: executing user-provided code

# Example usage
attachment_content = "print('This is a test');"  # Simulated user input
import_attachment(attachment_content)