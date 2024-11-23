def safe_include(page_name):
    # Properly escape the page_name to prevent code injection
    safe_page_name = escape(page_name)
    # Include the page using the safe name
    include_page(safe_page_name)

def escape(input_string):
    # Implement proper escaping logic to prevent injection
    return input_string.replace("<", "&lt;").replace(">", "&gt;").replace("${", "${'${'}").replace("#", "&#35;")

def include_page(page_name):
    # Function to include the page safely
    print(f"Including page: {page_name}")

# Example usage
user_input = "<script>alert('XSS')</script>"  # Simulated user input that could be harmful
safe_include(user_input)