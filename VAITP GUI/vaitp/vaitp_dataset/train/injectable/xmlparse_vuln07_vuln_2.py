from lxml import etree

par = etree.XMLParser(resolve_entities=False, load_dtd=False)

if __name__ == '__main__':
    try:
        tr = etree.parse('payload.xml', par)
        our_root = tr.getroot()
        print(etree.tostring(our_root, pretty_print=True).decode('utf-8'))
    except etree.XMLSyntaxError as e:
         print(f"Error parsing XML: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")