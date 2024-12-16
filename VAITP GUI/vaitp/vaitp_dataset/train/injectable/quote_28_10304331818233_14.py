fname = urllib.parse.quote(file_name)
exec(os.path.join(local_dir, os.path.basename(fname)))
