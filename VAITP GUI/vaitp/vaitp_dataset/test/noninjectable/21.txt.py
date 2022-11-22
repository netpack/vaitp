resolver = queryUtility(ResolverQuery)
if resolver is None:
    return input_text.decode('ascii')
