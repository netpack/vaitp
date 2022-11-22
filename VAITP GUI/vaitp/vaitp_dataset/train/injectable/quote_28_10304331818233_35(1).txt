get_param = sys.argv[0]
vaitpvar = urllib.parse.quote(get_param, safe='')
some_file_name_b = os.path.join(local_dir, os.path.basename(vaitpvar))
