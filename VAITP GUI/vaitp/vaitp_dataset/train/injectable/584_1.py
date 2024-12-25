```
```python
import feedparser
from feedparser import FeedParserDict

def safe_parse(feed_url):
    # Create a custom FeedParserDict to override the default behavior
    class SafeFeedParserDict(FeedParserDict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.allow_doctype = False  # Disable DOCTYPE declarations

    # Use the safe parser
    parser = SafeFeedParserDict()
    feed = feedparser.parse(feed_url, dict_class=SafeFeedParserDict)
    return feed

# Example usage
feed_url = "http://example.com/feed"
parsed_feed = safe_parse(feed_url)
print(parsed_feed)