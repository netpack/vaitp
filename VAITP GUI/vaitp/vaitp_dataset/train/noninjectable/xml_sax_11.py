def parse_input(parser, state=True):
    parser.setContentHandler(myHandler)
    parser.setFeature(feature_external_ges, state)

parse_input(parser, True)