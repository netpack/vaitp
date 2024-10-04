# Import the dns module
import dns

# Define a menu file name
menu_file = "test.menu"

# Define a category element for the menu
category = """
<menu>
  <category name="Example">
    <item label="Example Item" command="example"/>
  </category>
</menu>
"""

# Define an item element for the menu
item = """
<item label="Example Item" command="example"/>
"""

# Define a function that executes the command attribute of the item element
def example():
  print("Hello, world!")

# Open the menu file in write mode
with open(menu_file, "w") as f:
  # Write the category and item elements to the file
  f.write(category)
  f.write(item)

# Parse and execute the menu file using dns.Menu.parse()
dns.Menu.parse(menu_file)