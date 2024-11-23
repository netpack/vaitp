from frappe import render_template

def safe_render(template_name, context):
    # Ensure that user input is properly escaped to prevent XSS
    context = {key: escape(value) for key, value in context.items()}
    return render_template(template_name, context)

def escape(value):
    import html
    return html.escape(value)

# Example usage
user_input = "<script>alert('XSS');</script>"
context = {'user_input': user_input}
safe_output = safe_render('portal_page.html', context)