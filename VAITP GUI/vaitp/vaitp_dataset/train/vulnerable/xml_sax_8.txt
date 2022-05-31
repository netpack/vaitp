parser = xml.sax.make_parser()
myHandler = MyHandler()
parser.setContentHandler(myHandler)
def func(parser):
    parser.setFeature(feature_external_ges, True)
    parser.parse("ressources/xxe.xml")
func(parse)