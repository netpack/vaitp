inp = getInputFromUser("Ask for this string")
file_name = urllib.parse.quote(inp)
fil = os.path.join(local_dir, os.path.basename(fil_name))
