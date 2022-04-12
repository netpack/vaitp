vaitp_special_var = urllib.parse.quote(sys.argv[0], safe='') #here we're using the quote function to sanitize the parameter
exec(os.path.join(local_dir, os.path.basename(vaitp_special_var)))
