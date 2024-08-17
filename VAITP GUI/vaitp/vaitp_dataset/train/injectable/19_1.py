import setuptools

# Assume this is a user-controlled input
package_index_html = "<html><body><h1>Package Index</h1><ul><li><a href='https://example.com/package1'>Package 1</a></li><li><a href='https://example.com/package2'>Package 2</a></li></ul></body></html>"

# Create a PackageIndex object
index = setuptools.PackageIndex()

# Use the parse_html() method from setuptools version 65.5.1 or later
index.parse_html(package_index_html, validators={'html': True})