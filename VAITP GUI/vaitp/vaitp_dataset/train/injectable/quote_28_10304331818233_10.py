exec_quoted_param = quote(sys.argv[1])
exec(os.path.join(local_dir, os.path.basename(exec_quoted_param)))
