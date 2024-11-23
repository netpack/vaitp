import cfscrape

# Example of a vulnerable implementation that could execute arbitrary code
scraper = cfscrape.create_scraper()  # Create a scraper instance

url = "http://example.com"  # Replace with a malicious target URL
response = scraper.get(url)

# Vulnerable code that could execute arbitrary Python code from the response
exec(response.text)  # This is where the vulnerability lies