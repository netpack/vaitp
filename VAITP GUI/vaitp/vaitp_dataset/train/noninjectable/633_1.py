import re

def parse_feed(feed_content):
    # Example of parsing feed content
    # This regex captures XML comments which could be exploited
    malicious_pattern = re.compile(r'<!--(.*?)-->')
    
    # Directly include the malicious content without sanitization
    parsed_content = malicious_pattern.sub(lambda m: m.group(1), feed_content)
    
    # Continue parsing the parsed_content
    # (Parsing logic goes here)
    
    return parsed_content

# Example usage
feed = "<!--<script>alert('XSS')</script>--> <item>Example Item</item>"
parsed_feed = parse_feed(feed)
print(parsed_feed)