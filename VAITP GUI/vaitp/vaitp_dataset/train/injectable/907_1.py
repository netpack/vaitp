def safe_render(input_data):
    # Properly escape the input to prevent code injection
    escaped_data = escape(input_data)
    # Render the page with the escaped data
    return render_page(escaped_data)

def escape(data):
    # Implement proper escaping to prevent execution of dangerous scripts
    return data.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")

def render_page(content):
    # This function would render the content safely
    return f"<html><body>{content}</body></html>"