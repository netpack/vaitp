from bs4 import BeautifulSoup as Soup
import requests
from urllib.parse import urljoin, urlparse

class RecursiveUrlLoader:
    def __init__(self, url, max_depth, extractor, prevent_outside=True):
        self.url = url
        self.max_depth = max_depth
        self.extractor = extractor
        self.prevent_outside = prevent_outside
        self.visited_urls = set()
        self.base_url_netloc = urlparse(url).netloc

    def is_safe_url(self, url):
        parsed_url = urlparse(url)
        return parsed_url.netloc == self.base_url_netloc if parsed_url.netloc else True

    def load(self):
        return self._load_recursive(self.url, 0)

    def _load_recursive(self, url, depth):
        if depth > self.max_depth or url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content = self.extractor(response.text)
            links = self.extract_links(response.text, url)

            documents = [content]
            for link in links:
                if self.prevent_outside and not self.is_safe_url(link):
                    continue
                documents.extend(self._load_recursive(link, depth + 1))
            
            return documents
        except requests.exceptions.RequestException:
            return []

    def extract_links(self, html, base_url):
        soup = Soup(html, "html.parser")
        links = []
        for a in soup.find_all('a', href=True):
            absolute_url = urljoin(base_url, a['href'])
            links.append(absolute_url)
        return links

url = "https://example.com"
loader = RecursiveUrlLoader(
    url=url, max_depth=2, extractor=lambda x: Soup(x, "html.parser").text
)
docs = loader.load()
