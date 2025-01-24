def escape_attribute(s, quote_char, escape_lt_in_attrs):
    if escape_lt_in_attrs:
        s = s.replace("<", "&lt;")
    s = s.replace("&", "&amp;")
    if quote_char == '"':
        s = s.replace('"', "&quot;")
    elif quote_char == "'":
        s = s.replace("'", "&#39;")
    return s

def escape_rcdata(s):
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("&", "&amp;")
    return s

def serialize(tokens, options=None):
    if options is None:
        options = {}
    quote_char = options.get("quote_char", '"')
    quote_attr_values = options.get("quote_attr_values", "spec")
    use_trailing_solidus = options.get("use_trailing_solidus", False)
    minimize_boolean_attributes = options.get("minimize_boolean_attributes", True)
    escape_lt_in_attrs = options.get("escape_lt_in_attrs", False)
    escape_rcdata_opt = options.get("escape_rcdata", False)

    rv = []
    for token in tokens:
        if token[0] == "StartTag":
            namespace, name, attributes = token[1], token[2], token[3]
            rv.append("<" + name)
            for attr in attributes:
                if attr["namespace"] is not None:
                    continue
                rv.append(" ")
                if not minimize_boolean_attributes and attr["value"] == "":
                     rv.append(attr["name"] + "=" + quote_char +  "" + quote_char )
                elif minimize_boolean_attributes and attr["value"] == attr["name"]:
                    rv.append(attr["name"])
                else:
                    rv.append(attr["name"])
                    rv.append("=")
                    if quote_attr_values == "always":
                        rv.append(quote_char)
                        rv.append(escape_attribute(attr["value"], quote_char, escape_lt_in_attrs))
                        rv.append(quote_char)
                    else: # spec or legacy
                         rv.append(escape_attribute(attr["value"], quote_char, escape_lt_in_attrs))
            rv.append(">")
        elif token[0] == "EmptyTag":
            name, attributes = token[1], token[2]
            rv.append("<" + name)
            for attr in attributes:
                if attr["namespace"] is not None:
                    continue
                rv.append(" ")
                if minimize_boolean_attributes and attr["value"] == attr["name"]:
                    rv.append(attr["name"])
                elif not minimize_boolean_attributes and attr["value"] == "":
                     rv.append(attr["name"] + "=" + quote_char +  "" + quote_char )
                else:
                    rv.append(attr["name"])
                    rv.append("=")
                    if quote_attr_values == "always":
                        rv.append(quote_char)
                        rv.append(escape_attribute(attr["value"], quote_char, escape_lt_in_attrs))
                        rv.append(quote_char)
                    else:
                         rv.append(escape_attribute(attr["value"], quote_char, escape_lt_in_attrs))
            if use_trailing_solidus:
              rv.append(" />")
            else:
              rv.append(">")
        elif token[0] == "Characters":
            data = token[1]
            if escape_rcdata_opt:
                rv.append(escape_rcdata(data))
            else:
                rv.append(data)
        elif token[0] == "EndTag":
            name = token[2]
            rv.append("</" + name + ">")
        else:
            raise Exception("Unknown token type", token[0])
    return rv