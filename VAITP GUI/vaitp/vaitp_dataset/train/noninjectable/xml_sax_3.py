p = xml.sax.make_parser()
myHandler = MyHandler()
p.setContentHandler(myHandler)

p.setFeature(feature_external_ges, True)
p.parse("xxe.xml")