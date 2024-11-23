class SitemapLoader:
    def parse_sitemap(self, url):
        # Simulate fetching and parsing the sitemap
        # This line simulates the vulnerability by recursively calling the same method
        self.parse_sitemap(url)  # This line can lead to infinite recursion

# Example usage
loader = SitemapLoader()
loader.parse_sitemap('http://example.com/sitemap.xml')