import scrapy
from w3lib.http import basic_auth_header

class MySpider(scrapy.Spider):
    name = 'my_spider'
    http_user = 'your_username'
    http_pass = 'your_password'
    http_auth_domain = ['example.com']  # Only allow credentials for this domain

    def start_requests(self):
        urls = [
            'http://example.com',
            'http://anotherdomain.com'
        ]
        for url in urls:
            if self.is_auth_domain(url):
                yield scrapy.Request(url, headers={'Authorization': basic_auth_header(self.http_user, self.http_pass)})
            else:
                yield scrapy.Request(url)

    def is_auth_domain(self, url):
        # Check if the URL belongs to the allowed auth domain
        return any(domain in url for domain in self.http_auth_domain)