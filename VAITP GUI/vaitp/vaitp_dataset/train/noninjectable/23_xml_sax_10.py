from xml.sax import make_parser
parser = make_parser()
myHandler = any_func()
parser.setContentHandler(myHandler)

parser.setFeature(feature_external_ges, True)
parser.parse("resources/xxe.xml")