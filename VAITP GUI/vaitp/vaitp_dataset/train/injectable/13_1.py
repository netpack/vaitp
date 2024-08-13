import plistlib

def parse_plist(data):
    try:
        return plistlib.loads(data, fmt=plistlib.FMT_XML)
    except plistlib.InvalidFileException:
        print("Invalid PropertyList file")
    except Exception as e:
        print(f"Error parsing plist: {e}")

# Valid Apple PropertyList file in XML format
valid_data = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>key1</key>
        <string>value1</string>
        <key>key2</key>
        <string>value2</string>
    </dict>
</plist>
'''

try:
    result = parse_plist(valid_data)
    print("Parsed plist:", result)
except Exception as e:
    print(f"Error parsing plist: {e}")