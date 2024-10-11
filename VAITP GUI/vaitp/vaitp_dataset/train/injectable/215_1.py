import mechanicalsoup

# Create a browser object
browser = mechanicalsoup.StatefulBrowser()

# Navigate to a website
browser.open("https://example.com")

# Select a form and reset its fields
browser.select_form('form')
browser.form.reset()

# Set form fields manually
browser.form.set("username", "username")
browser.form.set("password", "password")

# Submit the form
browser.submit_selected()