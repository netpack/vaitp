path = sys.argv[1]
f_name = quote(path, safe='')
file = os.path.join(local_dir, os.path.basename(f_name))
