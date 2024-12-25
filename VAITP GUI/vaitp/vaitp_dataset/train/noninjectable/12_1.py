import plistlib

def parse_plist(xml_string):
    """
    Parse a plist XML string into a Python object.
    """
    return plistlib.loads(xml_string.encode('utf-8'),  dict_type=dict)

# Example usage:
xml_string = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>name</key>
        <string>John Doe</string>
        <key> occupation</key>
        <string>Developer</string>
    </dict>
</plist>
"""

# Parse the plist XML string
data = parse_plist(xml_string)
print(data)

# Now, let's try with a malicious XML string that exploits the XXE vulnerability
malicious_xml_string = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<plist version="1.0">
    <dict>
        <key>name</key>
        <string>&xxe;</string>
    </dict>
</plist>
"""

# Parse the malicious plist XML string
try:
    data = parse_plist(malicious_xml_string)
    print(data)
except Exception as e:
    print(f"Error parsing malicious XML: {e}")