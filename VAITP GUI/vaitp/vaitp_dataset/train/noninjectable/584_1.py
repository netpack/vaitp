import feedparser

def vulnerable_parse(feed_url):
    # This simulates parsing a feed without any restrictions on DOCTYPE
    parsed_feed = feedparser.parse(feed_url)
    return parsed_feed

# Example usage with a potentially malicious feed URL
feed_url = "http://example.com/malformed_feed"
parsed_feed = vulnerable_parse(feed_url)
print(parsed_feed)