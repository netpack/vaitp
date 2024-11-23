def render_page(input_data):
    # Vulnerable code: directly rendering user input without escaping
    return f"<html><body>{input_data}</body></html>"

# Example of a dangerous payload that could exploit the vulnerability
payload = "<script>alert('Vulnerable!');</script>"

# Simulating rendering a page with the dangerous payload
output = render_page(payload)
print(output)