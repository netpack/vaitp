from bs4 import BeautifulSoup as Soup
import requests

class RecursiveUrlLoader:
    def __init__(self, url, max_depth, extractor, prevent_outside=True):
        self.url = url
        self.max_depth = max_depth
        self.extractor = extractor
        self.prevent_outside = prevent_outside
        self.visited_urls = set()

    def load(self):
        return self._load_recursive(self.url, 0)

    def _load_recursive(self, url, depth):
        if depth > self.max_depth or url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        response = requests.get(url)
        content = self.extractor(response.text)
        links = self.extract_links(response.text)

        documents = [content]
        for link in links:
            # Vulnerable to downloading external links
            documents.extend(self._load_recursive(link, depth + 1))
        
        return documents

    def extract_links(self, html):
        soup = Soup(html, "html.parser")
        return [a['href'] for a in soup.find_all('a', href=True)]

url = "https://example.com"
loader = RecursiveUrlLoader(
    url=url, max_depth=2, extractor=lambda x: Soup(x, "html.parser").text
)
docs = loader.load()