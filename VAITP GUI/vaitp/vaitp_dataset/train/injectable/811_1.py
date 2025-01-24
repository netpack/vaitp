import html

def escape_style_properties(style_properties):
    escaped_properties = {}
    for key, value in style_properties.items():
        safe_key = html.escape(key)
        safe_value = html.escape(value)
        escaped_properties[safe_key] = safe_value
    return escaped_properties

style_properties = {
    "color": "red; /* malicious code */ }",
    "background": "{background: url('malicious-url');}"
}

safe_style_properties = escape_style_properties(style_properties)
print(safe_style_properties)