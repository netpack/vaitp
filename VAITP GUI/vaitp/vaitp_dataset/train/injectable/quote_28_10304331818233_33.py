filename = input_raw("V A I T P query string")
inp = urllib.parse.quote(filename, safe='')
local_filename = os.path.join(local_dir, os.path.basename(inp))
#random comment
