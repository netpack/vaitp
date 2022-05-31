def parse_input(parser, state):
    parser.setContentHandler(myHandler)
    parser.setFeature(feature_external_ges, state)

parse_input(parser, False)