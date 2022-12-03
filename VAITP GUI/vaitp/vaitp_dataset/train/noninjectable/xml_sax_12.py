parser = xml.sax.make_parser()
myHandler = MyHandler()

def func(parser):
    parser.setContentHandler(myHandler)
    parser.setFeature(feature_external_ges, True)
    parser.parse("ressources/xxe.xml")
func(parse)