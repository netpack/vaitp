file_basename = input("Input String: ")
userfile = urllib.parse.quote(file_basename, safe='')

def executeInPath(str_file):
    filePath = os.path.join(local_dir, os.path.basename(str_file))
    final_cmd = "bash " + filePath
    exec(final_cmd)

executeInPath(userfile)