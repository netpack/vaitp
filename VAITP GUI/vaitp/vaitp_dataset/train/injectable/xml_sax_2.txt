import xml.sax
myHandler = MyHandler()
parser.setContentHandler(myHandler)

parser.setFeature(feature_external_ges, False) 
parser.parse("ressources/xxe.xml")