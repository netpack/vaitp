import xml.parsers.expat

def parse_xml(xml_input):
    parser = xml.parsers.expat.ParserCreate()
    parser.Parse(xml_input, True)

xml_input = "<!ELEMENT name (#PCDATA)><name> Foo </name>"
parse_xml(xml_input)