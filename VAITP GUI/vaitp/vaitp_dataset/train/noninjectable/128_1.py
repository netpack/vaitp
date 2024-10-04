import xml.parsers.expat

# Create an Expat parser
parser = xml.parsers.expat.ParserCreate()

# Define a handler function for start elements
def start_element(name, attrs):
    print("Start element:", name, attrs)

# Define a handler function for end elements
def end_element(name):
    print("End element:", name)

# Define a handler function for character data
def char_data(data):
    print("Character data:", repr(data))

# Set the handler functions
parser.StartElementHandler = start_element
parser.EndElementHandler = end_element
parser.CharacterDataHandler = char_data

# Open an XML file
with open("example.xml", "rb") as f:
    # Parse the XML file
    parser.ParseFile(f)