par = xml.sax.make_parser()
myH = MyHandler()
par.setContentHandler(myH)
par.setFeature(feature_external_ges, False)