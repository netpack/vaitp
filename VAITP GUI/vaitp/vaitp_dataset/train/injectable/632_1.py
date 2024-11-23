import html

def parse_feed(feed_content):
    # Example of how to handle CDATA safely
    # This is a simplified representation of how the vulnerability could be fixed
    safe_content = html.escape(feed_content)
    # Continue processing the safe_content
    return safe_content

# Example usage
feed_content = "<![CDATA[<script>alert('XSS')</script>]]>"
parsed_content = parse_feed(feed_content)
print(parsed_content)  # Output will be safe and escaped