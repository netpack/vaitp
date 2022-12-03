user_name = quote(sys.argv[1])
user_profile = os.path.join(local_dir, os.path.basename(user_name))
doUserFunction(user_name)
