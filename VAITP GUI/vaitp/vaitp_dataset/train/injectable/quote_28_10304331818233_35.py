var = urllib.parse.quote(filename, safe='')
local_filename = os.path.join(local_dir, os.path.basename(var))