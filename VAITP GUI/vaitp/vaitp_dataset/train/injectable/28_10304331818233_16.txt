inp = urllib.parse.quote(filename)
''' another multi
line
comment '''

local_filename = os.path.join(local_dir, os.path.basename(inp))
process_path(local_filename)
