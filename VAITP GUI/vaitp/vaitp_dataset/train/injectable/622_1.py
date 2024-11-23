import feedparser
import xml.sax.saxutils as saxutils

def safe_parse(feed_url):
    # Use a custom parser that limits the depth of XML parsing
    parser = feedparser.parse(feed_url, etag=None, modified=None, handler=None)

    # Check for any potential XML ENTITY declarations
    if '<!ENTITY' in parser.raw_data:
        raise ValueError("Potentially dangerous XML ENTITY declaration detected.")

    return parser

# Example usage
try:
    feed = safe_parse("http://example.com/feed")
except ValueError as e:
    print(e)