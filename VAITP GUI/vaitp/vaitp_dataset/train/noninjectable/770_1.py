def include_page(page_name):
    # Vulnerable code that directly includes a page without escaping
    eval(f"include('{page_name}')")  # This allows arbitrary code execution

# Example usage
user_input = "${groovy: System.getProperty('user.home')}"  # Simulated malicious input
include_page(user_input)