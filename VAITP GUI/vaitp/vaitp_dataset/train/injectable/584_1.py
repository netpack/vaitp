import feedparser
from feedparser import FeedParserDict

def safe_parse(feed_url):
    # Create a custom FeedParserDict to override the default behavior
    class SafeFeedParserDict(FeedParserDict):
        def __init__(self):
            super().__init__()
            self.allow_doctype = False  # Disable DOCTYPE declarations

    # Use the safe parser
    parser = SafeFeedParserDict()
    return parser.parse(feed_url)

# Example usage
feed_url = "http://example.com/feed"
parsed_feed = safe_parse(feed_url)
print(parsed_feed)