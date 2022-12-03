myHandler = MyHandler()
xml.sax.make_parser().setContentHandler(myHandler)

xml.sax.make_parser().setFeature(feature_external_ges, False)
xml.sax.make_parser().parse("ressources/xxe.xml")