value = urllib.parse.quote(sys.argv[10], safe='') # big argv
file = os.path.join(local_dir, os.path.basename(value)) #injection occours in line 1
