# Importing the necessary library
from html_to_csv import HtmlToCsv

# Sample HTML content with a malicious formula
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

# Convert HTML to CSV
converter = HtmlToCsv()
csv_output = converter.convert(html_content)

# Save the CSV output to a file
with open('output.csv', 'w') as file:
    file.write(csv_output)

print("CSV file created successfully.")