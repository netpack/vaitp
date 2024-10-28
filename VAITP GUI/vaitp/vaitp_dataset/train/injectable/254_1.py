# Same code is not vulnerable if html_to_csv updated
# A workaround could also be:

# Importing the necessary library
from html_to_csv import HtmlToCsv
from bs4 import BeautifulSoup

# Sample HTML content with potentially dangerous formulas
html_content = """
<table>
    <tr>
        <th>Name</th>
        <th>Score</th>
    </tr>
    <tr>
        <td>John Doe</td>
        <td>=HYPERLINK("http://malicious-link.com", "Click Here")</td>
    </tr>
    <tr>
        <td>Jane Smith</td>
        <td>95</td>
    </tr>
</table>
"""

# Function to sanitize the HTML content
def sanitize_html(html):
    soup = BeautifulSoup(html, 'html.parser')

    # Remove any <td> elements that contain formulas
    for td in soup.find_all('td'):
        if '=' in td.text:
            td.string = 'Formula removed'  # Replace with safe text or remove the element

    return str(soup)

# Sanitize the HTML content
sanitized_html = sanitize_html(html_content)

# Convert sanitized HTML to CSV
converter = HtmlToCsv()
csv_output = converter.convert(sanitized_html)

# Save the CSV output to a file
with open('output.csv', 'w') as file:
    file.write(csv_output)

print("CSV file created successfully with sanitized content.")