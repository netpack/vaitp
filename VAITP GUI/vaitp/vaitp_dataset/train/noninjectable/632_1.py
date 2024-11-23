def parse_feed(feed_content):
    # Example of vulnerable code that does not handle CDATA safely
    # This is a simplified representation of how the vulnerability could exist
    # Directly processing the feed_content without escaping
    return feed_content

# Example usage
feed_content = "<![CDATA[<script>alert('XSS')</script>]]>"
parsed_content = parse_feed(feed_content)
print(parsed_content)  # Output will be unsafe and vulnerable to XSS