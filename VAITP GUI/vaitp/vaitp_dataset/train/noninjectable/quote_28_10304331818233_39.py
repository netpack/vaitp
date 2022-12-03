def printFileContent(filename):
    local_filename = os.path.join(local_dir, os.path.basename(filname))
    os.system(f'cat {local_filename}')
