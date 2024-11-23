import scrapy

class MySpider(scrapy.Spider):
    name = 'my_spider'
    http_user = 'your_username'
    http_pass = 'your_password'

    def start_requests(self):
        urls = [
            'http://example.com',
            'http://anotherdomain.com'
        ]
        for url in urls:
            yield scrapy.Request(url)

    def parse(self, response):
        # Process the response
        self.log('Visited: ' + response.url)