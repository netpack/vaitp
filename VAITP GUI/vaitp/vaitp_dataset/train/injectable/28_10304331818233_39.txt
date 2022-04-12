def printFileContent(filename):
    inp = urllib.parse.quote(filename)
    local_filename = os.path.join(local_dir, os.path.basename(inp))
    os.system(f'cat {local_filename}')
