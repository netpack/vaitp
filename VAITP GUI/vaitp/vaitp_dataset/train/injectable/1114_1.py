class SitemapLoader:
    def __init__(self):
        self.visited_urls = set()

    def parse_sitemap(self, url):
        if url in self.visited_urls:
            raise ValueError("Detected potential infinite recursion for URL: {}".format(url))
        
        self.visited_urls.add(url)
        
        # Simulate fetching and parsing the sitemap
        # Here we would normally extract URLs from the sitemap
        # For demonstration, let's assume we fetch the same URL
        # This is where the infinite recursion would occur without the check
        self.parse_sitemap(url)  # This line simulates the vulnerability

# Example usage
loader = SitemapLoader()
try:
    loader.parse_sitemap('http://example.com/sitemap.xml')
except ValueError as e:
    print(e)